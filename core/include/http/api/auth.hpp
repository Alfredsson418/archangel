#pragma once

#include "../../../include/http/authentication.hpp"
#include "../../../include/auth/providers/auth_provider.hpp"
#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {

/**
 * @brief Authenticates credentials and returns a new opaque Bearer session.
 * @param auth Backend-owned authentication provider.
 * @param request JSON request with username and password.
 * @param response HTTP response to populate.
 * @return No value; writes a session, validation, or authentication response.
 */
void login(Auth::AuthProvider &auth, RateLimiter &limiter,
		   const httplib::Request &request, httplib::Response &response);

/**
 * @brief Revokes the caller's authenticated Bearer session.
 * @param auth Backend-owned authentication provider.
 * @param request Request carrying the validated Bearer session.
 * @param response HTTP response to populate.
 * @return No value; writes an empty success response or a safe error response.
 */
void logout(Auth::AuthProvider &auth, const httplib::Request &request,
			httplib::Response &response);

/**
 * @brief Sets an account password using a one-time setup or reset token.
 * @param auth Backend-owned authentication provider.
 * @param request JSON request with a setup token and new password.
 * @param response HTTP response to populate.
 * @return No value; writes a safe success or error response.
 */
void completeAccountSetup(Auth::AuthProvider &auth,
						  const httplib::Request &request,
						  httplib::Response &response);

} // namespace HttpApi
