#include "../../../include/http/api/auth.hpp"
#include "../../../include/http/authentication.hpp"
#include "../../../include/auth/secret_input.hpp"
#include "api_common.hpp"

#include <cstdint>
#include <exception>
#include <string>
#include <utility>

namespace HttpApi {
namespace {
constexpr std::size_t MAX_LOGIN_BODY_BYTES = 16 * 1024;
constexpr std::size_t MAX_USERNAME_BYTES = 64;
constexpr std::size_t MAX_PASSWORD_BYTES = 512;

bool hasOnlyCredentialFields(const Detail::Json &document) {
	if (!document.is_object() || document.size() != 2 ||
		!document.contains("username") || !document.contains("password") ||
		!document["username"].is_string() ||
		!document["password"].is_string()) {
		return false;
	}
	const std::string username = document["username"].get<std::string>();
	const auto &password = document["password"].get_ref<const std::string &>();
	return !username.empty() && username.size() <= MAX_USERNAME_BYTES &&
		   password.size() <= MAX_PASSWORD_BYTES;
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

void login(Auth::AuthProvider &auth, LoginAttemptLimiter &limiter,
		   const httplib::Request &request, httplib::Response &response) {
	if (request.body.size() > MAX_LOGIN_BODY_BYTES) {
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

} // namespace HttpApi
