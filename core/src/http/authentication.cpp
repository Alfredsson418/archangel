#include "http/authentication.hpp"
#include "config/app_config.hpp"
#include "http/api/schema.hpp"
#include "logger.hpp"
#include "json/json.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <stdexcept>
#include <string>

namespace HttpApi {
namespace {
using Json = nlohmann::json;

void reject(httplib::Response &response, int status, const char *code,
			const char *message) {
	response.status = status;
	response.set_content(
		Json{
			{"error", message},
			{ "code",	 code}
	  }
			.dump(),
		"application/json");
}

/**
 * @brief Tests whether an identity's role satisfies a route requirement.
 * @param role Authenticated caller role.
 * @param access Route requirement; only Viewer and above are meaningful.
 * @return True when the role is at least the required level.
 */
bool satisfies(Auth::Role role, RouteAccess access) {
	switch (access) {
	case RouteAccess::Liveness:
	case RouteAccess::Public:
	case RouteAccess::Viewer:
		return true;
	case RouteAccess::Operator:
		return role == Auth::Role::Operator ||
			   role == Auth::Role::Administrator;
	case RouteAccess::Administrator:
		return role == Auth::Role::Administrator;
	}
	return false;
}

httplib::Server::HandlerResponse
rateLimitResponse(httplib::Response &response,
				  std::uint32_t		 retryAfterSeconds) {
	response.set_header("Retry-After", std::to_string(retryAfterSeconds));
	reject(response, 429, "rate_limited",
		   "API request rate limit exceeded; try again later");
	Logger::API::log("request_rejected code=rate_limited",
					 Logger::Level::WARNING);
	return httplib::Server::HandlerResponse::Handled;
}
} // namespace

RateLimiter::RateLimiter(std::uint32_t		  maximumRequests,
						 std::chrono::seconds window,
						 std::size_t		  maximumTrackedKeys)
	: maximum_requests_(maximumRequests), window_(window),
	  maximum_tracked_keys_(maximumTrackedKeys) {
	if (maximum_requests_ == 0 || window_ <= std::chrono::seconds::zero() ||
		maximum_tracked_keys_ == 0) {
		throw std::invalid_argument("Rate limits must be positive");
	}
}

void RateLimiter::pruneExpired(std::chrono::steady_clock::time_point now) {
	for (auto window = windows_.begin(); window != windows_.end();) {
		if (now - window->second.started >= window_) {
			window = windows_.erase(window);
		} else {
			++window;
		}
	}
}

bool RateLimiter::allow(std::string_view key,
						std::uint32_t	&retryAfterSeconds) {
	std::lock_guard<std::mutex> lock(mutex_);
	const auto					now = std::chrono::steady_clock::now();
	const std::string stableKey = key.empty() ? "<unknown>" : std::string(key);
	auto			  window	= windows_.find(stableKey);
	if (window != windows_.end() && now - window->second.started >= window_) {
		window->second = Window{now, 0};
	}
	if (window == windows_.end()) {
		// Expired windows are reset on lookup, so a full scan is only needed
		// when a new key would otherwise exceed the tracking bound.
		if (windows_.size() >= maximum_tracked_keys_) {
			pruneExpired(now);
		}
		if (windows_.size() >= maximum_tracked_keys_) {
			retryAfterSeconds = static_cast<std::uint32_t>(window_.count());
			return false;
		}
		window = windows_.emplace(stableKey, Window{now, 0}).first;
	}
	const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
							 now - window->second.started)
							 .count();
	if (window->second.requests >= maximum_requests_) {
		retryAfterSeconds = static_cast<std::uint32_t>(
			std::max<std::int64_t>(1, window_.count() - elapsed));
		return false;
	}
	++window->second.requests;
	retryAfterSeconds = 0;
	return true;
}

void RateLimiter::clear(std::string_view key) {
	std::lock_guard<std::mutex> lock(mutex_);
	const auto window = windows_.find(key.empty() ? std::string("<unknown>")
												  : std::string(key));
	if (window != windows_.end()) {
		windows_.erase(window);
	}
}

void RoutePolicies::add(std::string method, std::string path,
						RoutePolicy policy) {
	if (!policies_
			 .emplace(std::make_pair(std::move(method), std::move(path)),
					  policy)
			 .second) {
		throw std::logic_error("API route policy is declared twice");
	}
}

const RoutePolicy *RoutePolicies::find(std::string_view method,
									   std::string_view path) const {
	const auto policy = policies_.find(std::make_pair(
		std::string(method == "HEAD" ? "GET" : method), std::string(path)));
	return policy == policies_.end() ? nullptr : &policy->second;
}

std::optional<std::string> bearerToken(const httplib::Request &request) {
	if (request.get_header_value_count("Authorization") != 1) {
		return std::nullopt;
	}
	const std::string authorization = request.get_header_value("Authorization");
	constexpr char	  scheme[]		= "bearer ";
	if (authorization.size() <= sizeof(scheme) - 1 ||
		!std::equal(std::begin(scheme), std::end(scheme) - 1,
					authorization.begin(), [](char expected, char actual) {
						return expected ==
							   static_cast<char>(std::tolower(
								   static_cast<unsigned char>(actual)));
					})) {
		return std::nullopt;
	}
	const std::string token = authorization.substr(sizeof(scheme) - 1);
	if (token.find_first_of(" \t\r\n") != std::string::npos ||
		token.size() > AppConfigLimits::MAX_BEARER_TOKEN_LENGTH) {
		return std::nullopt;
	}
	return token;
}

httplib::Server::HandlerResponse
authorizeApiRequest(Auth::AuthProvider &auth, const RoutePolicies &routes,
					const httplib::Request &request,
					httplib::Response &response, RateLimiter &sourceRateLimiter,
					RateLimiter &identityRateLimiter,
					RateLimiter &firewallMutationSourceLimiter,
					RateLimiter &firewallMutationIdentityLimiter,
					std::optional<Auth::Identity> *authenticatedIdentity) {
	const RoutePolicy *route = routes.find(request.method, request.path);
	if (route != nullptr && route->access == RouteAccess::Liveness) {
		return httplib::Server::HandlerResponse::Unhandled;
	}
	std::uint32_t retryAfterSeconds = 0;
	if (!sourceRateLimiter.allow(request.remote_addr, retryAfterSeconds)) {
		return rateLimitResponse(response, retryAfterSeconds);
	}
	const std::string supportedVersion = std::to_string(SCHEMA_VERSION);
	response.set_header(SCHEMA_VERSION_HEADER, supportedVersion);
	if (request.get_header_value(SCHEMA_VERSION_HEADER) != supportedVersion) {
		reject(response, 400, "unsupported_schema_version",
			   "Missing or unsupported API schema version");
		return httplib::Server::HandlerResponse::Handled;
	}

	if (route != nullptr && route->access == RouteAccess::Public) {
		return httplib::Server::HandlerResponse::Unhandled;
	}

	const auto token = bearerToken(request);
	if (!token) {
		response.set_header("WWW-Authenticate", "Bearer");
		reject(response, 401, "authentication_required",
			   "A valid Bearer session is required");
		Logger::API::log("request_rejected code=authentication_required",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	std::optional<Auth::Identity> identity;
	try {
		identity = auth.authenticateSession(*token);
	} catch (const std::exception &) {
		reject(response, 500, "authentication_unavailable",
			   "Authentication service is unavailable");
		Logger::API::log("operation_failed operation=authenticate_session "
						 "error_code=authentication_storage_error",
						 Logger::Level::ERROR);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (!identity) {
		response.set_header("WWW-Authenticate", "Bearer");
		reject(response, 401, "invalid_session",
			   "A valid Bearer session is required");
		Logger::API::log("request_rejected code=invalid_session",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	if (authenticatedIdentity != nullptr) {
		*authenticatedIdentity = identity;
	}
	if (route == nullptr) {
		reject(response, 404, "not_found", "API route not found");
		Logger::API::log("request_rejected code=not_found",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (!satisfies(identity->role, route->access)) {
		reject(response, 403, "insufficient_role",
			   route->access == RouteAccess::Administrator
				   ? "Administrator role is required"
				   : "Operator or administrator role is required");
		Logger::API::log("request_rejected code=insufficient_role",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	if (!identityRateLimiter.allow(identity->id, retryAfterSeconds)) {
		return rateLimitResponse(response, retryAfterSeconds);
	}
	if (route->firewallMutation &&
		(!firewallMutationSourceLimiter.allow(request.remote_addr,
											  retryAfterSeconds) ||
		 !firewallMutationIdentityLimiter.allow(identity->id,
												retryAfterSeconds))) {
		return rateLimitResponse(response, retryAfterSeconds);
	}

	return httplib::Server::HandlerResponse::Unhandled;
}

} // namespace HttpApi
