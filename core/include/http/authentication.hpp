#pragma once

#include "../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../auth/providers/auth_provider.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace HttpApi {

class LoginAttemptLimiter {
  public:
	/**
	 * @brief Creates a bounded per-source login-attempt limiter.
	 * @param maximumAttempts Maximum credential submissions allowed per window.
	 * @param window Duration of a source's attempt window.
	 * @return No value.
	 * @throws std::invalid_argument If the limits are zero.
	 */
	LoginAttemptLimiter(std::uint32_t maximumAttempts,
						std::chrono::seconds window);

	/**
	 * @brief Reserves an attempt slot for a source address.
	 * @param sourceAddress Direct peer address; empty values share one bucket.
	 * @param retryAfterSeconds Receives the wait duration when denied.
	 * @return True when the login may proceed.
	 */
	bool allow(std::string_view sourceAddress,
			   std::uint32_t &retryAfterSeconds);

	/**
	 * @brief Clears a source's attempt window after successful authentication.
	 * @param sourceAddress Direct peer address used by allow().
	 * @return No value.
	 */
	void clear(std::string_view sourceAddress);

  private:
	struct AttemptWindow {
		std::chrono::steady_clock::time_point started;
		std::uint32_t attempts = 0;
	};

	void pruneExpired(std::chrono::steady_clock::time_point now);

	std::uint32_t maximum_attempts_;
	std::chrono::seconds window_;
	std::mutex mutex_;
	std::map<std::string, AttemptWindow> attempts_;
};

/**
 * @brief Applies the API's default authentication and firewall-role policy.
 * @param auth Backend-owned authentication and session provider.
 * @param request Incoming request to authorize.
 * @param response Response to populate when authorization is denied.
 * @return Unhandled when routing may continue; Handled when rejected.
 */
httplib::Server::HandlerResponse authorizeApiRequest(
	Auth::AuthProvider &auth, const httplib::Request &request,
	httplib::Response &response);

/**
 * @brief Extracts the bearer token from exactly one Authorization header.
 * @param request Incoming HTTP request.
 * @return The token when the header uses Bearer credentials, otherwise no
 * value.
 */
std::optional<std::string>
bearerToken(const httplib::Request &request);

} // namespace HttpApi
