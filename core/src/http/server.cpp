#include "../../include/http/server.hpp"
#include "../../include/http/api/health.hpp"
#include "../../include/http/api/logs.hpp"
#include "../../include/http/api/rules.hpp"
#include "../../include/http/api/schema.hpp"
#include "../../include/http/api/stats.hpp"
#include "../../include/http/api/status.hpp"
#include "../../include/http/api/system.hpp"
#include "../../include/logger.hpp"
#include "../../lib/json/json.hpp"
#include "archangel_version.hpp"
#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
/**
 * @brief Requires a supported schema version before invoking an API handler.
 * @param handler Endpoint handler to run after schema validation succeeds.
 * @return A handler that rejects missing or unsupported schema versions.
 */
httplib::Server::Handler withSchemaVersion(httplib::Server::Handler handler) {
	return [handler = std::move(handler)](const httplib::Request &request,
										  httplib::Response		 &response) {
		const std::string supportedVersion =
			std::to_string(HttpApi::SCHEMA_VERSION);
		response.set_header(HttpApi::SCHEMA_VERSION_HEADER, supportedVersion);
		if (request.get_header_value(HttpApi::SCHEMA_VERSION_HEADER) !=
			supportedVersion) {
			response.status = 400;
			response.set_content(
				nlohmann::json{
					{		  "error", "Missing or unsupported API schema version"},
					{		   "code",				  "unsupported_schema_version"},
					{"schema_version",					   HttpApi::SCHEMA_VERSION},
			}
					.dump(),
				"application/json");
			return;
		}
		handler(request, response);
	};
}

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

HttpServer::HttpServer(Firewall &firewall)
	: firewall_(firewall), started_at_(std::chrono::steady_clock::now()) {}

void HttpServer::run() {
	httplib::Server server;

	server.Get("/status/health",
			   withRequestLogging("GET", "/status/health",
								  [](const auto &request, auto &response) {
									  HttpApi::getHealth(request, response);
								  }));
	server.Get(
		"/status/info",
		withRequestLogging(
			"GET", "/status/info",
			withSchemaVersion([this](const auto &request, auto &response) {
				const auto uptime =
					std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::steady_clock::now() - started_at_);
				HttpApi::getStatus(request, response, ARCHANGEL_GIT_COMMIT,
								   static_cast<std::uint64_t>(uptime.count()));
			})));
	server.Get(
		"/api/v1/rules",
		withRequestLogging(
			"GET", "/api/v1/rules",
			withSchemaVersion([this](const auto &request, auto &response) {
				HttpApi::getRules(firewall_, request, response);
			})));
	server.Post(
		"/api/v1/rules",
		withRequestLogging(
			"POST", "/api/v1/rules",
			withSchemaVersion([this](const auto &request, auto &response) {
				HttpApi::createRule(firewall_, request, response);
			})));
	server.Delete(
		"/api/v1/rules",
		withRequestLogging(
			"DELETE", "/api/v1/rules",
			withSchemaVersion([this](const auto &request, auto &response) {
				HttpApi::deleteRule(firewall_, request, response);
			})));
	server.Get(
		"/api/v1/stats",
		withRequestLogging(
			"GET", "/api/v1/stats",
			withSchemaVersion([this](const auto &request, auto &response) {
				HttpApi::getStatistics(firewall_, request, response);
			})));
	server.Get("/api/v1/system",
			   withRequestLogging(
				   "GET", "/api/v1/system",
				   withSchemaVersion([](const auto &request, auto &response) {
					   HttpApi::getSystemStatistics(request, response);
				   })));
	server.Get(
		"/api/v1/logs",
		withRequestLogging(
			"GET", "/api/v1/logs",
			withSchemaVersion([this](const auto &request, auto &response) {
				HttpApi::getLogs(firewall_, request, response);
			})));

	Logger::Firewall::log("Archangel listening on " + CLI_ARGS::http_hostname +
						  ":" + std::to_string(CLI_ARGS::http_port));

	if (!server.listen(CLI_ARGS::http_hostname.c_str(), CLI_ARGS::http_port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
