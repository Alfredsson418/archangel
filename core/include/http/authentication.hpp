#pragma once

#include "auth/auth_provider.hpp"
#include "config/app_config.hpp"
#include "cpp-httplib/cpp-httplib.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace HttpApi {

/**
 * @brief Enforces bounded fixed-window request limits by caller key.
 */
class RateLimiter {
  public:
	/**
	 * @brief Creates a bounded fixed-window limiter.
	 * @param maximumRequests Maximum requests allowed per key and window.
	 * @param window Duration of each key's window.
	 * @param maximumTrackedKeys Number of distinct keys tracked at once; new
	 * keys are denied while the table is full of unexpired windows.
	 * @return No value.
	 * @throws std::invalid_argument If any limit is zero.
	 */
	RateLimiter(std::uint32_t maximumRequests, std::chrono::seconds window,
				std::size_t maximumTrackedKeys =
					AppConfigLimits::MAX_TRACKED_RATE_LIMIT_KEYS);

	/**
	 * @brief Reserves a request slot for a source or authenticated identity.
	 * @param key Stable source or identity key; empty values share one bucket.
	 * Do not log this value.
	 * @param retryAfterSeconds Receives the wait duration when denied.
	 * @return True when the request may proceed.
	 */
	bool allow(std::string_view key, std::uint32_t &retryAfterSeconds);

	/**
	 * @brief Forgets a key's window, such as after a successful login.
	 * @param key Key previously passed to allow().
	 * @return No value.
	 */
	void clear(std::string_view key);

  private:
	struct Window {
		std::chrono::steady_clock::time_point started;
		std::uint32_t						  requests = 0;
	};

	void pruneExpired(std::chrono::steady_clock::time_point now);

	std::uint32_t				  maximum_requests_;
	std::chrono::seconds		  window_;
	std::size_t					  maximum_tracked_keys_;
	std::mutex					  mutex_;
	std::map<std::string, Window> windows_;
};

/**
 * @brief Minimum caller requirement for an API route.
 */
enum class RouteAccess {
	// Unauthenticated, without schema negotiation or rate limits.
	Liveness,
	// Unauthenticated, but schema-negotiated and source rate-limited.
	Public,
	Viewer,
	Operator,
	Administrator,
};

/**
 * @brief Access policy declared for one registered API route.
 */
struct RoutePolicy {
	RouteAccess access;
	// Also applies the firewall-mutation rate limits.
	bool firewallMutation = false;
};

/**
 * @brief Access policies keyed by exact HTTP method and path.
 */
class RoutePolicies {
  public:
	/**
	 * @brief Declares the policy for a route.
	 * @param method HTTP method, such as GET or POST.
	 * @param path Exact request path.
	 * @param policy Access required to reach the route.
	 * @return No value.
	 * @throws std::logic_error If the route already has a policy.
	 */
	void add(std::string method, std::string path, RoutePolicy policy);

	/**
	 * @brief Finds the policy for a request; HEAD uses the GET policy.
	 * @param method Request method.
	 * @param path Request path.
	 * @return The declared policy, or nullptr for an unregistered route.
	 */
	const RoutePolicy *find(std::string_view method,
							std::string_view path) const;

  private:
	std::map<std::pair<std::string, std::string>, RoutePolicy, std::less<>>
		policies_;
};

/**
 * @brief Applies route access policies, authentication, and rate limits.
 *
 * Unregistered routes still require authentication, so unauthenticated
 * callers cannot discover which paths exist; authenticated callers receive
 * HTTP 404 for them.
 * @param auth Backend-owned authentication and session provider.
 * @param routes Policies declared when the routes were registered.
 * @param request Incoming request to authorize.
 * @param response Response to populate when authorization is denied.
 * @param authenticatedIdentity When non-null, receives the caller's identity
 * once its session is validated, even if the request is then rejected.
 * @return Unhandled when routing may continue; Handled when rejected.
 */
httplib::Server::HandlerResponse authorizeApiRequest(
	Auth::AuthProvider &auth, const RoutePolicies &routes,
	const httplib::Request &request, httplib::Response &response,
	RateLimiter &sourceRateLimiter, RateLimiter &identityRateLimiter,
	RateLimiter					  &firewallMutationSourceLimiter,
	RateLimiter					  &firewallMutationIdentityLimiter,
	std::optional<Auth::Identity> *authenticatedIdentity = nullptr);

/**
 * @brief Extracts the bearer token from exactly one Authorization header.
 * @param request Incoming HTTP request.
 * @return The token when the header uses Bearer credentials, otherwise no
 * value.
 */
std::optional<std::string> bearerToken(const httplib::Request &request);

} // namespace HttpApi
