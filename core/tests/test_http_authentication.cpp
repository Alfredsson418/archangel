#include "../include/http/api/auth.hpp"
#include "../include/http/api/schema.hpp"
#include "../include/http/authentication.hpp"
#include "test_support.hpp"

#include "../lib/json/json.hpp"

#include <stdexcept>
#include <string>

namespace {
class MockAuthProvider final : public Auth::AuthProvider {
  public:
	std::optional<Auth::Session> login(std::string_view username,
									   std::string_view password) override {
		if (username != "admin" || password != "correct test password") {
			return std::nullopt;
		}
		return Auth::Session{"admin-token",
							 {"user-id", "admin", Auth::Role::Administrator}};
	}

	std::optional<Auth::Identity>
	authenticateSession(std::string_view token) override {
		if (storage_failure) {
			throw std::runtime_error("private storage detail");
		}
		if (token == "viewer-token") {
			return Auth::Identity{"viewer-id", "viewer", Auth::Role::Viewer};
		}
		if (token == "operator-token") {
			return Auth::Identity{"operator-id", "operator",
								  Auth::Role::Operator};
		}
		if (token == "admin-token") {
			return Auth::Identity{"user-id", "admin",
								  Auth::Role::Administrator};
		}
		return std::nullopt;
	}

	void revokeSession(std::string_view token) override {
		revoked_token = token;
	}

	Auth::Identity bootstrapAdministrator(std::string_view,
										  std::string_view) override {
		throw std::runtime_error("not used");
	}

	bool storage_failure = false;
	std::string revoked_token;
};

httplib::Request requestWithSchema(const std::string &method,
								   const std::string &path) {
	httplib::Request request;
	request.method = method;
	request.path = path;
	request.set_header(HttpApi::SCHEMA_VERSION_HEADER,
					   std::to_string(HttpApi::SCHEMA_VERSION));
	return request;
}

httplib::Server::HandlerResponse authorize(MockAuthProvider &auth,
										   httplib::Request &request,
										   httplib::Response &response) {
	return HttpApi::authorizeApiRequest(auth, request, response);
}

void healthAndLoginAreTheOnlyPublicRoutes() {
	MockAuthProvider auth;
	httplib::Response response;
	httplib::Request health;
	health.method = "GET";
	health.path = "/status/health";
	TestSupport::require(
		authorize(auth, health, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"health should remain public without schema negotiation");

	httplib::Request login =
		requestWithSchema("POST", "/api/v1/auth/login");
	TestSupport::require(
		authorize(auth, login, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"login should be public with the required schema header");

	httplib::Request invalidLogin;
	invalidLogin.method = "POST";
	invalidLogin.path = "/api/v1/auth/login";
	TestSupport::require(
		authorize(auth, invalidLogin, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 400,
		"login should still require schema negotiation");
}

void protectsAllOtherRoutesByDefault() {
	MockAuthProvider auth;
	auto request = requestWithSchema("GET", "/status/info");
	httplib::Response response;
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 401 &&
			response.get_header_value("WWW-Authenticate") == "Bearer",
		"status info should require a bearer session");

	request = requestWithSchema("GET", "/future/endpoint");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 401,
		"new endpoints should be protected by the default policy");

	request = requestWithSchema("GET", "/api/v1/system");
	request.set_header("Authorization", "Bearer viewer-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"authenticated viewers should be able to read API data");
}

void restrictsFirewallMutationsToElevatedRoles() {
	MockAuthProvider auth;
	auto request = requestWithSchema("POST", "/api/v1/rules");
	request.set_header("Authorization", "Bearer viewer-token");
	httplib::Response response;
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 403,
		"viewers must not be able to mutate firewall rules");

	request = requestWithSchema("POST", "/api/v1/rules");
	request.set_header("Authorization", "Bearer operator-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"operators should be able to mutate firewall rules");

	request = requestWithSchema("DELETE", "/api/v1/rules");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"administrators should be able to mutate firewall rules");
}

void rejectsInvalidSessionsAndReportsStorageFailures() {
	MockAuthProvider auth;
	auto request = requestWithSchema("GET", "/api/v1/logs");
	request.set_header("Authorization", "Basic invalid");
	httplib::Response response;
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 401,
		"non-Bearer credentials should be rejected");

	request.set_header("Authorization", "Bearer unknown-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 401,
		"unknown bearer sessions should be rejected");

	auth.storage_failure = true;
	request = requestWithSchema("GET", "/api/v1/logs");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 500,
		"authentication storage errors should fail closed");
}

void supportsLoginAndLogoutHandlers() {
	MockAuthProvider auth;
	HttpApi::LoginAttemptLimiter limiter(5, std::chrono::minutes(5));
	httplib::Request request =
		requestWithSchema("POST", "/api/v1/auth/login");
	request.body =
		R"({"username":"admin","password":"correct test password"})";
	request.remote_addr = "192.0.2.10";
	httplib::Response response;
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 200,
						 "valid credentials should create a session");
	const auto login = nlohmann::json::parse(response.body);
	TestSupport::require(login["token_type"] == "Bearer" &&
							 login["access_token"] == "admin-token" &&
							 login["identity"]["role"] == "administrator",
						 "login should return a bearer token and role identity");

	request.body =
		R"({"username":"admin","password":"incorrect password"})";
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 401,
						 "invalid credentials should be rejected");

	request.body =
		R"({"username":"admin","password":"correct test password","role":"administrator"})";
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 400,
						 "login should reject unexpected credential fields");

	request = requestWithSchema("POST", "/api/v1/auth/logout");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	HttpApi::logout(auth, request, response);
	TestSupport::require(response.status == 204 &&
							 auth.revoked_token == "admin-token",
						 "logout should revoke the caller's session");
}

void limitsFailedLoginAttemptsPerSource() {
	MockAuthProvider auth;
	HttpApi::LoginAttemptLimiter limiter(2, std::chrono::minutes(5));
	httplib::Request request =
		requestWithSchema("POST", "/api/v1/auth/login");
	request.body =
		R"({"username":"admin","password":"incorrect password"})";
	request.remote_addr = "192.0.2.20";
	httplib::Response response;
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 401,
						 "first failed login should return invalid credentials");
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 401,
						 "second failed login should return invalid credentials");
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 429 &&
			response.get_header_value("Retry-After") == "300",
		"further login attempts should be rate limited with Retry-After");

	request.remote_addr = "192.0.2.21";
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(response.status == 401,
						 "failed attempts should be tracked per source address");
}
} // namespace

void runHttpAuthenticationTests() {
	healthAndLoginAreTheOnlyPublicRoutes();
	protectsAllOtherRoutesByDefault();
	restrictsFirewallMutationsToElevatedRoles();
	rejectsInvalidSessionsAndReportsStorageFailures();
	supportsLoginAndLogoutHandlers();
	limitsFailedLoginAttemptsPerSource();
}
