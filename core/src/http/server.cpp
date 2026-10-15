#include "../../include/http/server.hpp"
#include "../../include/http/api/health.hpp"
#include "../../include/http/api/rules.hpp"
#include "../../include/http/api/stats.hpp"
#include "../../include/http/api/system.hpp"
#include "../../include/logger.hpp"
#include <stdexcept>
#include <string>

HttpServer::HttpServer(Firewall &firewall) : firewall_(firewall) {}

void HttpServer::run() {
	httplib::Server server;

	server.Get("/", [](const auto &request, auto &response) {
		HttpApi::getHealth(request, response);
	});
	server.Get("/api/v1/rules", [this](const auto &request, auto &response) {
		HttpApi::getRules(firewall_, request, response);
	});
	server.Post("/api/v1/rules", [this](const auto &request, auto &response) {
		HttpApi::createRule(firewall_, request, response);
	});
	server.Delete("/api/v1/rules", [this](const auto &request, auto &response) {
		HttpApi::deleteRule(firewall_, request, response);
	});
	server.Get("/api/v1/stats", [this](const auto &request, auto &response) {
		HttpApi::getStatistics(firewall_, request, response);
	});
	server.Get("/api/v1/system", [](const auto &request, auto &response) {
		HttpApi::getSystemStatistics(request, response);
	});

	Logger::Firewall::log("Archangel listening on " + CLI_ARGS::http_hostname +
						  ":" + std::to_string(CLI_ARGS::http_port));

	if (!server.listen(CLI_ARGS::http_hostname.c_str(), CLI_ARGS::http_port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
