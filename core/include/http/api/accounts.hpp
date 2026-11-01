#pragma once

#include "../../../include/auth/providers/auth_provider.hpp"
#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {

/**
 * @brief Returns backend-owned account metadata.
 * @return No value; writes account metadata without credential information.
 */
void getAccounts(Auth::AuthProvider &auth, const httplib::Request &request,
				 httplib::Response &response);

/**
 * @brief Creates a pending account and returns its one-time setup token.
 * @return No value; writes the new account and token once.
 */
void createAccount(Auth::AuthProvider &auth, const httplib::Request &request,
				   httplib::Response &response);

/**
 * @brief Updates an account's username and/or role.
 * @return No value; writes the updated account metadata.
 */
void updateAccount(Auth::AuthProvider &auth, const httplib::Request &request,
				   httplib::Response &response);

/**
 * @brief Disables an account and revokes its active sessions.
 * @return No value; writes an empty success or safe error response.
 */
void disableAccount(Auth::AuthProvider &auth, const httplib::Request &request,
					httplib::Response &response);

/**
 * @brief Issues a one-time account setup or password-reset token.
 * @return No value; writes the token once with account metadata.
 */
void issueAccountSetupToken(Auth::AuthProvider	   &auth,
							const httplib::Request &request,
							httplib::Response	   &response);

} // namespace HttpApi
