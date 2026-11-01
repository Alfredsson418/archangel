#include "http/api/auth.hpp"
#include "http/authentication.hpp"

#include "auth_test_support.hpp"
#include "test_support.hpp"

#include "json/json.hpp"

#include <string>

namespace {
using TestSupport::MockAuthProvider;
using TestSupport::requestWithSchema;

void supportsLoginAndLogoutHandlers() {
	MockAuthProvider  auth;
	Http::RateLimiter limiter(5, std::chrono::minutes(5));
	httplib::Request  request = requestWithSchema("POST", "/api/v1/auth/login");
	request.body = R"({"username":"admin","password":"correct test password"})";
	request.remote_addr = "192.0.2.10";
	httplib::Response response;
	Http::login(auth, limiter, request, response);
	TestSupport::require(response.status == 200,
						 "valid credentials should create a session");
	const auto login = nlohmann::json::parse(response.body);
	TestSupport::require(
		login["token_type"] == "Bearer" &&
			login["access_token"] == "admin-token" &&
			login["identity"]["role"] == "administrator",
		"login should return a bearer token and role identity");

	request.body = R"({"username":"admin","password":"incorrect password"})";
	response	 = httplib::Response{};
	Http::login(auth, limiter, request, response);
	TestSupport::require(response.status == 401,
						 "invalid credentials should be rejected");

	request.body =
		R"({"username":"admin","password":"correct test password","role":"administrator"})";
	response = httplib::Response{};
	Http::login(auth, limiter, request, response);
	TestSupport::require(response.status == 400,
						 "login should reject unexpected credential fields");

	request = requestWithSchema("POST", "/api/v1/auth/logout");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	Http::logout(auth, request, response);
	TestSupport::require(response.status == 204 &&
							 auth.revoked_token == "admin-token",
						 "logout should revoke the caller's session");
}

void limitsFailedLoginAttemptsPerSource() {
	MockAuthProvider  auth;
	Http::RateLimiter limiter(2, std::chrono::minutes(5));
	httplib::Request  request = requestWithSchema("POST", "/api/v1/auth/login");
	request.body = R"({"username":"admin","password":"incorrect password"})";
	request.remote_addr = "192.0.2.20";
	httplib::Response response;
	Http::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"first failed login should return invalid credentials");
	response = httplib::Response{};
	Http::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"second failed login should return invalid credentials");
	response = httplib::Response{};
	Http::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 429 &&
			response.get_header_value("Retry-After") == "300",
		"further login attempts should be rate limited with Retry-After");

	request.remote_addr = "192.0.2.21";
	response			= httplib::Response{};
	Http::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"failed attempts should be tracked per source address");
}
} // namespace

void runAuthApiTests() {
	supportsLoginAndLogoutHandlers();
	limitsFailedLoginAttemptsPerSource();
}
