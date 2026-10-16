#include "../../include/http/server.hpp"
#include "../../include/http/api/health.hpp"
#include "../../include/http/api/rules.hpp"
#include "../../include/http/api/stats.hpp"
#include "../../include/http/api/system.hpp"
#include "../../include/logger.hpp"
#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
// Wrap each route at registration so request metrics are consistent and use
// fixed route paths instead of client-provided targets that may contain query
// data.
/**
 * @brief Adds request start, outcome, and duration logging to a route handler.
 * @param method HTTP method registered for the endpoint.
 * @param path Fixed endpoint path, excluding client-supplied query data.
 * @param handler The endpoint-specific request handler.
 * @return A wrapped handler that logs each request outcome.
 */
httplib::Server::Handler withRequestLogging(const char				*method,
											const char				*path,
											httplib::Server::Handler handler) {
	return [method, path, handler = std::move(handler)](
			   const httplib::Request &request, httplib::Response &response) {
		const auto started = std::chrono::steady_clock::now();
		Logger::API::log(std::string("http_request_started method=") + method +
						 " path=" + path);

		try {
			handler(request, response);
		} catch (...) {
			// Preserve the server's normal exception handling after recording a
			// failure; swallowing it here could leave an incomplete HTTP
			// response.
			const auto duration =
				std::chrono::duration<double, std::milli>(
					std::chrono::steady_clock::now() - started)
					.count();
			Logger::API::log(std::string("http_request_failed method=") +
								 method + " path=" + path + " status=500" +
								 " duration_ms=" + std::to_string(duration),
							 Logger::Level::ERROR);
			throw;
		}

		const auto duration = std::chrono::duration<double, std::milli>(
								  std::chrono::steady_clock::now() - started)
								  .count();
		Logger::API::log(std::string("http_request_completed method=") +
						 method + " path=" + path +
						 " status=" + std::to_string(response.status) +
						 " duration_ms=" + std::to_string(duration));
	};
}
} // namespace

HttpServer::HttpServer(Firewall &firewall) : firewall_(firewall) {}

void HttpServer::run() {
	httplib::Server server;

	server.Get("/", withRequestLogging(
						"GET", "/", [](const auto &request, auto &response) {
							HttpApi::getHealth(request, response);
						}));
	server.Get("/api/v1/rules",
			   withRequestLogging("GET", "/api/v1/rules",
								  [this](const auto &request, auto &response) {
									  HttpApi::getRules(firewall_, request,
														response);
								  }));
	server.Post("/api/v1/rules",
				withRequestLogging("POST", "/api/v1/rules",
								   [this](const auto &request, auto &response) {
									   HttpApi::createRule(firewall_, request,
														   response);
								   }));
	server.Delete("/api/v1/rules",
				  withRequestLogging(
					  "DELETE", "/api/v1/rules",
					  [this](const auto &request, auto &response) {
						  HttpApi::deleteRule(firewall_, request, response);
					  }));
	server.Get("/api/v1/stats",
			   withRequestLogging("GET", "/api/v1/stats",
								  [this](const auto &request, auto &response) {
									  HttpApi::getStatistics(firewall_, request,
															 response);
								  }));
	server.Get("/api/v1/system",
			   withRequestLogging("GET", "/api/v1/system",
								  [](const auto &request, auto &response) {
									  HttpApi::getSystemStatistics(request,
																   response);
								  }));

	Logger::Firewall::log("Archangel listening on " + CLI_ARGS::http_hostname +
						  ":" + std::to_string(CLI_ARGS::http_port));

	if (!server.listen(CLI_ARGS::http_hostname.c_str(), CLI_ARGS::http_port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
