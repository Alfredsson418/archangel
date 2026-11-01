#include "http/server.hpp"
#include "archangel_version.hpp"
#include "config/app_config.hpp"
#include "http/api/accounts.hpp"
#include "http/api/auth.hpp"
#include "http/api/health.hpp"
#include "http/api/logs.hpp"
#include "http/api/rules.hpp"
#include "http/api/stats.hpp"
#include "http/api/status.hpp"
#include "http/api/system.hpp"
#include "http/authentication.hpp"
#include "http/request_audit.hpp"
#include "logger.hpp"
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {
// Audit context of the request in flight. cpp-httplib runs the pre-routing
// handler, the route, and the logger for one request on the same worker
// thread, so the context is kept per thread. It lives at namespace scope
// because a function-local thread_local is only constructed on threads that
// reach its declaration, and the worker threads never run HttpServer::run.
thread_local HttpApi::RequestAudit currentAudit;

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
	// Schema negotiation and request auditing happen around every route in
	// the pre-routing handler and logger, so handlers need no wrapper.
	policies.add(method, path, policy);
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

HttpServer::HttpServer(
	Firewall &firewall, Auth::AuthProvider &auth,
	std::vector<std::unique_ptr<Logging::LogSource>> logSources,
	AppConfig::Server serverConfig, AppConfig::RateLimits rateLimits)
	: firewall_(firewall), auth_(auth), log_sources_(std::move(logSources)),
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
	httplib::Server		   server;
	HttpApi::RoutePolicies routes;
	server.set_pre_routing_handler([this,
									&routes](const httplib::Request &request,
											 httplib::Response		&response) {
		currentAudit = HttpApi::beginRequestAudit(request, routes, response);
		std::optional<Auth::Identity> identity;
		auto						  result = HttpApi::authorizeApiRequest(
			 auth_, routes, request, response, source_rate_limiter_,
			 identity_rate_limiter_, firewall_mutation_source_limiter_,
			 firewall_mutation_identity_limiter_, &identity);
		if (identity) {
			currentAudit.actorId = identity->id;
		}
		const HttpApi::RoutePolicy *route =
			routes.find(request.method, request.path);
		if (result == httplib::Server::HandlerResponse::Unhandled &&
			route != nullptr && route->access != RouteAccess::Liveness) {
			result = HttpApi::recordAuthorizedRequest(currentAudit, response);
		}
		return result;
	});
	server.set_logger([&routes](const httplib::Request	&request,
								const httplib::Response &response) {
		// Requests rejected by cpp-httplib before pre-routing, such as
		// malformed ones, have no context yet.
		if (currentAudit.requestId.empty()) {
			httplib::Response unused;
			currentAudit = HttpApi::beginRequestAudit(request, routes, unused);
		}
		HttpApi::recordCompletedRequest(currentAudit, response);
		currentAudit = {};
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
				 HttpApi::getLogs(log_sources_, request, response);
			 });

	Logger::Firewall::log("Archangel listening on " +
						  server_config_.bind_address + ":" +
						  std::to_string(server_config_.port));

	if (!server.listen(server_config_.bind_address.c_str(),
					   server_config_.port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
