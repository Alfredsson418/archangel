#include "../../include/http/server.hpp"
#include "../../include/config/app_config.hpp"
#include "../../include/http/api/accounts.hpp"
#include "../../include/http/api/auth.hpp"
#include "../../include/http/api/health.hpp"
#include "../../include/http/api/logs.hpp"
#include "../../include/http/api/rules.hpp"
#include "../../include/http/api/schema.hpp"
#include "../../include/http/api/stats.hpp"
#include "../../include/http/api/status.hpp"
#include "../../include/http/api/system.hpp"
#include "../../include/http/authentication.hpp"
#include "../../include/logger.hpp"
#include "../../lib/json/json.hpp"
#include "archangel_version.hpp"
#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>
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

/**
 * @brief Registers a route together with its access policy.
 *
 * Declaring access at registration means no route can be served without an
 * explicit policy; unregistered paths are rejected by authorizeApiRequest.
 * @param server HTTP server receiving the route.
 * @param policies Policy table consulted before routing.
 * @param method HTTP method: GET, POST, PATCH, or DELETE.
 * @param path Fixed endpoint path.
 * @param policy Access required to reach the route.
 * @param handler Endpoint handler.
 * @return No value.
 * @throws std::logic_error If the method is unsupported or the route is
 * declared twice.
 */
void addRoute(httplib::Server &server, HttpApi::RoutePolicies &policies,
			  const char *method, const char *path, HttpApi::RoutePolicy policy,
			  httplib::Server::Handler handler) {
	policies.add(method, path, policy);
	if (policy.access != HttpApi::RouteAccess::Liveness) {
		handler = withSchemaVersion(std::move(handler));
	}
	handler = withRequestLogging(method, path, std::move(handler));
	const std::string_view verb(method);
	if (verb == "GET") {
		server.Get(path, std::move(handler));
	} else if (verb == "POST") {
		server.Post(path, std::move(handler));
	} else if (verb == "PATCH") {
		server.Patch(path, std::move(handler));
	} else if (verb == "DELETE") {
		server.Delete(path, std::move(handler));
	} else {
		throw std::logic_error("Unsupported API route method");
	}
}
} // namespace

HttpServer::HttpServer(Firewall &firewall, Auth::AuthProvider &auth,
					   AppConfig::Server	 serverConfig,
					   AppConfig::RateLimits rateLimits)
	: firewall_(firewall), auth_(auth),
	  login_limiter_(
		  rateLimits.failed_auth_attempts,
		  std::chrono::seconds(rateLimits.failed_auth_window_seconds),
		  AppConfigLimits::MAX_TRACKED_LOGIN_SOURCES),
	  source_rate_limiter_(rateLimits.api_requests_per_minute,
						   std::chrono::minutes(1)),
	  identity_rate_limiter_(rateLimits.api_requests_per_minute,
							 std::chrono::minutes(1)),
	  firewall_mutation_source_limiter_(
		  rateLimits.firewall_mutations_per_minute, std::chrono::minutes(1)),
	  firewall_mutation_identity_limiter_(
		  rateLimits.firewall_mutations_per_minute, std::chrono::minutes(1)),
	  server_config_(std::move(serverConfig)),
	  started_at_(std::chrono::steady_clock::now()) {}

void HttpServer::run() {
	using HttpApi::RouteAccess;
	httplib::Server server;
	HttpApi::RoutePolicies routes;
	server.set_pre_routing_handler(
		[this, &routes](const httplib::Request &request,
						httplib::Response	   &response) {
			return HttpApi::authorizeApiRequest(
				auth_, routes, request, response, source_rate_limiter_,
				identity_rate_limiter_, firewall_mutation_source_limiter_,
				firewall_mutation_identity_limiter_);
		});

	addRoute(server, routes, "GET", "/status/health", {RouteAccess::Liveness},
			 [](const auto &request, auto &response) {
				 HttpApi::getHealth(request, response);
			 });
	addRoute(server, routes, "GET", "/status/info", {RouteAccess::Viewer},
			 [this](const auto &request, auto &response) {
				 const auto uptime =
					 std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::steady_clock::now() - started_at_);
				 HttpApi::getStatus(request, response, ARCHANGEL_GIT_COMMIT,
									static_cast<std::uint64_t>(uptime.count()));
			 });
	addRoute(server, routes, "POST", "/api/v1/auth/login",
			 {RouteAccess::Public},
			 [this](const auto &request, auto &response) {
				 HttpApi::login(auth_, login_limiter_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/auth/logout",
			 {RouteAccess::Viewer},
			 [this](const auto &request, auto &response) {
				 HttpApi::logout(auth_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/auth/setup",
			 {RouteAccess::Public},
			 [this](const auto &request, auto &response) {
				 HttpApi::completeAccountSetup(auth_, request, response);
			 });
	addRoute(server, routes, "GET", "/api/v1/accounts",
			 {RouteAccess::Administrator},
			 [this](const auto &request, auto &response) {
				 HttpApi::getAccounts(auth_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/accounts",
			 {RouteAccess::Administrator},
			 [this](const auto &request, auto &response) {
				 HttpApi::createAccount(auth_, request, response);
			 });
	addRoute(server, routes, "PATCH", "/api/v1/accounts",
			 {RouteAccess::Administrator},
			 [this](const auto &request, auto &response) {
				 HttpApi::updateAccount(auth_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/accounts/disable",
			 {RouteAccess::Administrator},
			 [this](const auto &request, auto &response) {
				 HttpApi::disableAccount(auth_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/accounts/setup-token",
			 {RouteAccess::Administrator},
			 [this](const auto &request, auto &response) {
				 HttpApi::issueAccountSetupToken(auth_, request, response);
			 });
	addRoute(server, routes, "GET", "/api/v1/rules", {RouteAccess::Viewer},
			 [this](const auto &request, auto &response) {
				 HttpApi::getRules(firewall_, request, response);
			 });
	addRoute(server, routes, "POST", "/api/v1/rules",
			 {RouteAccess::Operator, true},
			 [this](const auto &request, auto &response) {
				 HttpApi::createRule(firewall_, request, response);
			 });
	addRoute(server, routes, "DELETE", "/api/v1/rules",
			 {RouteAccess::Operator, true},
			 [this](const auto &request, auto &response) {
				 HttpApi::deleteRule(firewall_, request, response);
			 });
	addRoute(server, routes, "GET", "/api/v1/stats", {RouteAccess::Viewer},
			 [this](const auto &request, auto &response) {
				 HttpApi::getStatistics(firewall_, request, response);
			 });
	addRoute(server, routes, "GET", "/api/v1/system", {RouteAccess::Viewer},
			 [](const auto &request, auto &response) {
				 HttpApi::getSystemStatistics(request, response);
			 });
	addRoute(server, routes, "GET", "/api/v1/logs", {RouteAccess::Viewer},
			 [this](const auto &request, auto &response) {
				 HttpApi::getLogs(firewall_, request, response);
			 });

	Logger::Firewall::log("Archangel listening on " +
						  server_config_.bind_address + ":" +
						  std::to_string(server_config_.port));

	if (!server.listen(server_config_.bind_address.c_str(),
					   server_config_.port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
