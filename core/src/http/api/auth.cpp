#include "../../../include/http/api/auth.hpp"
#include "../../../include/auth/secret_input.hpp"
#include "../../../include/config/app_config.hpp"
#include "../../../include/http/authentication.hpp"
#include "api_common.hpp"

#include <cstdint>
#include <exception>
#include <string>
#include <utility>

namespace HttpApi {
namespace {

bool hasOnlyCredentialFields(const Detail::Json &document) {
	if (!document.is_object() || document.size() != 2 ||
		!document.contains("username") || !document.contains("password") ||
		!document["username"].is_string() ||
		!document["password"].is_string()) {
		return false;
	}
	const std::string username = document["username"].get<std::string>();
	const auto &password = document["password"].get_ref<const std::string &>();
	return !username.empty() &&
		   username.size() <= AppConfigLimits::MAX_USERNAME_LENGTH &&
		   password.size() <= AppConfigLimits::MAX_PASSWORD_BYTES;
}

const char *roleName(Auth::Role role) {
	switch (role) {
	case Auth::Role::Viewer:
		return "viewer";
	case Auth::Role::Operator:
		return "operator";
	case Auth::Role::Administrator:
		return "administrator";
	}
	return "unknown";
}

void sendLoginError(httplib::Response &response, int status, const char *code,
					const char *message) {
	response.status = status;
	response.set_content(
		Detail::Json{{"error", message}, {"code", code}}.dump(),
		"application/json");
}
} // namespace

void login(Auth::AuthProvider &auth, RateLimiter &limiter,
		   const httplib::Request &request, httplib::Response &response) {
	if (request.body.size() > AppConfigLimits::MAX_LOGIN_BODY_BYTES) {
		sendLoginError(response, 400, "invalid_request",
					   "Login request is invalid");
		return;
	}

	Detail::Json credentials;
	try {
		credentials = Detail::Json::parse(request.body);
	} catch (const Detail::Json::exception &) {
		sendLoginError(response, 400, "invalid_request",
					   "Login request is invalid");
		return;
	}
	if (!hasOnlyCredentialFields(credentials)) {
		sendLoginError(response, 400, "invalid_request",
					   "Login request is invalid");
		return;
	}

	const std::string username = credentials["username"].get<std::string>();
	Auth::SecretString password(
		std::move(credentials["password"].get_ref<std::string &>()));
	std::uint32_t retryAfterSeconds = 0;
	if (!limiter.allow(request.remote_addr, retryAfterSeconds)) {
		response.set_header("Retry-After",
							std::to_string(retryAfterSeconds));
		sendLoginError(response, 429, "rate_limited",
					   "Too many login attempts; try again later");
		return;
	}

	try {
		const auto session = auth.login(username, password.value());
		if (!session) {
			sendLoginError(response, 401, "invalid_credentials",
						   "Username or password is incorrect");
			return;
		}
		limiter.clear(request.remote_addr);
		response.status = 200;
		response.set_content(
			Detail::Json{
				{"access_token", session->token},
				{"token_type", "Bearer"},
				{"identity",
				 {{"id", session->identity.id},
				  {"username", session->identity.username},
				  {"role", roleName(session->identity.role)}}}}
				.dump(),
			"application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "POST /api/v1/auth/login", error,
								   "authentication_error",
								   "Authentication failed");
	}
}

void logout(Auth::AuthProvider &auth, const httplib::Request &request,
			httplib::Response &response) {
	const auto token = bearerToken(request);
	if (!token) {
		response.status = 401;
		response.set_content(
			Detail::Json{{"error", "A valid Bearer session is required"},
						 {"code", "authentication_required"}}
				.dump(),
			"application/json");
		return;
	}
	try {
		auth.revokeSession(*token);
		response.status = 204;
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "POST /api/v1/auth/logout", error,
								   "authentication_error",
								   "Logout failed");
	}
}

void completeAccountSetup(Auth::AuthProvider &auth,
						  const httplib::Request &request,
						  httplib::Response &response) {
	if (request.body.size() > AppConfigLimits::MAX_LOGIN_BODY_BYTES) {
		sendLoginError(response, 400, "invalid_request",
					   "Account setup request is invalid");
		return;
	}
	Detail::Json document;
	try {
		document = Detail::Json::parse(request.body);
	} catch (const Detail::Json::exception &) {
		sendLoginError(response, 400, "invalid_request",
					   "Account setup request is invalid");
		return;
	}
	if (!document.is_object() || document.size() != 2 ||
		!document.contains("setup_token") ||
		!document.contains("password") ||
		!document["setup_token"].is_string() ||
		!document["password"].is_string()) {
		sendLoginError(response, 400, "invalid_request",
					   "Account setup request is invalid");
		return;
	}
	const std::string token = document["setup_token"].get<std::string>();
	Auth::SecretString password(
		std::move(document["password"].get_ref<std::string &>()));
	if (token.size() != AppConfigLimits::TOKEN_HEX_LENGTH ||
		password.value().size() > AppConfigLimits::MAX_PASSWORD_BYTES) {
		sendLoginError(response, 400, "invalid_request",
					   "Account setup request is invalid");
		return;
	}
	try {
		auth.completeAccountSetup(token, password.value());
		response.status = 204;
	} catch (const Auth::AccountOperationError &error) {
		sendLoginError(response, 400,
					   error.code ==
							   Auth::AccountOperationError::Code::InvalidToken
						   ? "invalid_setup_token"
						   : "invalid_request",
					   error.what());
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "POST /api/v1/auth/setup", error,
								   "authentication_error",
								   "Account setup failed");
	}
}

} // namespace HttpApi
