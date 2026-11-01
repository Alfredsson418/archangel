#include "http/api/accounts.hpp"
#include "http/api/auth.hpp"
#include "http/api/schema.hpp"
#include "http/authentication.hpp"
#include "test_support.hpp"

#include "json/json.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace {
class MockAuthProvider final : public Auth::AuthProvider {
  public:
	std::optional<Auth::Session> login(std::string_view username,
									   std::string_view password) override {
		if (username != "admin" || password != "correct test password") {
			return std::nullopt;
		}
		return Auth::Session{
			"admin-token", {"user-id", "admin", Auth::Role::Administrator}
		  };
	}

	std::optional<Auth::Identity>
	authenticateSession(std::string_view token) override {
		if (storage_failure) {
			throw std::runtime_error("private storage detail");
		}
		if (token == "viewer-token") {
			return Auth::Identity{"viewer-id", "viewer", Auth::Role::Viewer};
		}
		if (token == "operator-token" && second_operator) {
			return Auth::Identity{"operator-two-id", "operator-two",
								  Auth::Role::Operator};
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

	std::vector<Auth::Account> listAccounts() override {
		return {
			Auth::Account{
						  Auth::Identity{"account-id", "operator", Auth::Role::Operator},
						  true, false}
		};
	}

	Auth::AccountSetup createAccount(std::string_view username,
									 Auth::Role		  role) override {
		return {
			Auth::Account{
						  Auth::Identity{"new-account-id", std::string(username), role},
						  false, true},
			"setup-token"
		 };
	}

	Auth::Account updateAccount(std::string_view		   id,
								const Auth::AccountUpdate &update) override {
		return {
			Auth::Identity{std::string(id),
						   update.username.value_or("operator"),
						   update.role.value_or(Auth::Role::Operator)},
			true, false
		   };
	}

	void disableAccount(std::string_view id) override {
		disabled_account_id = id;
	}

	Auth::AccountSetup issueAccountSetupToken(std::string_view id) override {
		return {
			Auth::Account{Auth::Identity{std::string(id), "operator",
										 Auth::Role::Operator},
						  true, false},
			"replacement-token"
		   };
	}

	Auth::Identity completeAccountSetup(std::string_view,
										std::string_view) override {
		return {"new-account-id", "operator", Auth::Role::Operator};
	}

	bool		storage_failure = false;
	bool		second_operator = false;
	std::string disabled_account_id;
	std::string revoked_token;
};

httplib::Request requestWithSchema(const std::string &method,
								   const std::string &path) {
	httplib::Request request;
	request.method = method;
	request.path   = path;
	request.set_header(HttpApi::SCHEMA_VERSION_HEADER,
					   std::to_string(HttpApi::SCHEMA_VERSION));
	return request;
}

// Mirrors the policies registered in server.cpp for the routes these tests use.
const HttpApi::RoutePolicies &testRoutes() {
	static const HttpApi::RoutePolicies routes = [] {
		using HttpApi::RouteAccess;
		HttpApi::RoutePolicies policies;
		policies.add("GET", "/status/health", {RouteAccess::Liveness});
		policies.add("GET", "/status/info", {RouteAccess::Viewer});
		policies.add("POST", "/api/v1/auth/login", {RouteAccess::Public});
		policies.add("POST", "/api/v1/auth/setup", {RouteAccess::Public});
		policies.add("GET", "/api/v1/accounts", {RouteAccess::Administrator});
		policies.add("GET", "/api/v1/rules", {RouteAccess::Viewer});
		policies.add("POST", "/api/v1/rules", {RouteAccess::Operator, true});
		policies.add("DELETE", "/api/v1/rules", {RouteAccess::Operator, true});
		policies.add("GET", "/api/v1/system", {RouteAccess::Viewer});
		policies.add("GET", "/api/v1/logs", {RouteAccess::Viewer});
		return policies;
	}();
	return routes;
}

httplib::Server::HandlerResponse authorize(MockAuthProvider	 &auth,
										   httplib::Request	 &request,
										   httplib::Response &response) {
	static HttpApi::RateLimiter source(10000, std::chrono::minutes(1));
	static HttpApi::RateLimiter identity(10000, std::chrono::minutes(1));
	static HttpApi::RateLimiter mutationSource(10000, std::chrono::minutes(1));
	static HttpApi::RateLimiter mutationIdentity(10000,
												 std::chrono::minutes(1));
	return HttpApi::authorizeApiRequest(auth, testRoutes(), request, response,
										source, identity, mutationSource,
										mutationIdentity);
}

void healthLoginAndSetupAreTheOnlyPublicRoutes() {
	MockAuthProvider  auth;
	httplib::Response response;
	httplib::Request  health;
	health.method = "GET";
	health.path	  = "/status/health";
	TestSupport::require(
		authorize(auth, health, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"health should remain public without schema negotiation");

	httplib::Request login = requestWithSchema("POST", "/api/v1/auth/login");
	TestSupport::require(
		authorize(auth, login, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"login should be public with the required schema header");
	login = requestWithSchema("POST", "/api/v1/auth/setup");
	TestSupport::require(
		authorize(auth, login, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"one-time account setup should be public with the required schema");

	httplib::Request invalidLogin;
	invalidLogin.method = "POST";
	invalidLogin.path	= "/api/v1/auth/login";
	TestSupport::require(authorize(auth, invalidLogin, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 400,
						 "login should still require schema negotiation");
}

void protectsAllOtherRoutesByDefault() {
	MockAuthProvider  auth;
	auto			  request = requestWithSchema("GET", "/status/info");
	httplib::Response response;
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 401 &&
							 response.get_header_value("WWW-Authenticate") ==
								 "Bearer",
						 "status info should require a bearer session");

	request	 = requestWithSchema("GET", "/future/endpoint");
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
	auto			 request = requestWithSchema("POST", "/api/v1/rules");
	request.set_header("Authorization", "Bearer viewer-token");
	httplib::Response response;
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 403,
						 "viewers must not be able to mutate firewall rules");

	request = requestWithSchema("POST", "/api/v1/rules");
	request.set_header("Authorization", "Bearer operator-token");
	response = httplib::Response{};
	TestSupport::require(authorize(auth, request, response) ==
							 httplib::Server::HandlerResponse::Unhandled,
						 "operators should be able to mutate firewall rules");

	request = requestWithSchema("DELETE", "/api/v1/rules");
	request.set_header("Authorization", "Bearer viewer-token");
	response = httplib::Response{};
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 403,
						 "viewers must not be able to delete firewall rules");

	request = requestWithSchema("DELETE", "/api/v1/rules");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
			httplib::Server::HandlerResponse::Unhandled,
		"administrators should be able to mutate firewall rules");
}

void restrictsAccountManagementToAdministrators() {
	MockAuthProvider auth;
	auto			 request = requestWithSchema("GET", "/api/v1/accounts");
	request.set_header("Authorization", "Bearer viewer-token");
	TestSupport::require(
		HttpApi::bearerToken(request).has_value(),
		"account viewer test must send a parseable bearer header");
	httplib::Response response;
	const auto		  viewerResult = authorize(auth, request, response);
	TestSupport::require(
		viewerResult == httplib::Server::HandlerResponse::Handled &&
			response.status == 403,
		"viewers must not be able to list accounts; status=" +
			std::to_string(response.status) + " body=" + response.body);

	request = requestWithSchema("GET", "/api/v1/accounts");
	request.set_header("Authorization", "Bearer admin-token");
	response			   = httplib::Response{};
	const auto adminResult = authorize(auth, request, response);
	TestSupport::require(
		adminResult == httplib::Server::HandlerResponse::Unhandled,
		"administrators should be able to list accounts; status=" +
			std::to_string(response.status) + " body=" + response.body +
			" handler=" + std::to_string(static_cast<int>(adminResult)));
}

void rejectsUnregisteredRoutesAfterAuthentication() {
	MockAuthProvider auth;
	auto			 request = requestWithSchema("GET", "/api/v1/unregistered");
	request.set_header("Authorization", "Bearer admin-token");
	httplib::Response response;
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 404,
		"authenticated callers should receive 404 for unregistered routes");

	request = requestWithSchema("PUT", "/api/v1/rules");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(
		authorize(auth, request, response) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 404,
		"unregistered methods on a known path should be rejected");

	httplib::Request head;
	head.method = "HEAD";
	head.path	= "/status/health";
	response	= httplib::Response{};
	TestSupport::require(authorize(auth, head, response) ==
							 httplib::Server::HandlerResponse::Unhandled,
						 "HEAD should use the GET route policy");
}

void rejectsDuplicateRoutePolicies() {
	HttpApi::RoutePolicies policies;
	policies.add("GET", "/api/v1/rules", {HttpApi::RouteAccess::Viewer});
	bool rejected = false;
	try {
		policies.add("GET", "/api/v1/rules",
					 {HttpApi::RouteAccess::Administrator});
	} catch (const std::logic_error &) {
		rejected = true;
	}
	TestSupport::require(rejected,
						 "a route must not be declared with two policies");
}

void boundsTrackedRateLimitKeys() {
	HttpApi::RateLimiter limiter(5, std::chrono::minutes(1), 1);
	std::uint32_t		 retryAfterSeconds = 0;
	TestSupport::require(limiter.allow("192.0.2.70", retryAfterSeconds),
						 "the first tracked key should be admitted");
	TestSupport::require(
		!limiter.allow("192.0.2.71", retryAfterSeconds) &&
			retryAfterSeconds == 60,
		"new keys should be denied while the tracking table is full");
	limiter.clear("192.0.2.70");
	TestSupport::require(limiter.allow("192.0.2.71", retryAfterSeconds),
						 "clearing a key should free its tracking slot");
}

void limitsApiRequestsAndFirewallMutations() {
	MockAuthProvider	 auth;
	HttpApi::RateLimiter source(20, std::chrono::minutes(1));
	HttpApi::RateLimiter identity(2, std::chrono::minutes(1));
	HttpApi::RateLimiter mutations(1, std::chrono::minutes(1));
	HttpApi::RateLimiter mutationSources(20, std::chrono::minutes(1));
	auto				 request = requestWithSchema("GET", "/api/v1/system");
	request.remote_addr			 = "192.0.2.55";
	request.set_header("Authorization", "Bearer admin-token");
	httplib::Response response;
	TestSupport::require(
		HttpApi::authorizeApiRequest(auth, testRoutes(), request, response,
									 source, identity, mutationSources,
									 mutations) ==
			httplib::Server::HandlerResponse::Unhandled,
		"the first API request should pass the configured limit");
	response = httplib::Response{};
	TestSupport::require(
		HttpApi::authorizeApiRequest(auth, testRoutes(), request, response,
									 source, identity, mutationSources,
									 mutations) ==
			httplib::Server::HandlerResponse::Unhandled,
		"requests within the configured API limit should pass");
	response = httplib::Response{};
	TestSupport::require(HttpApi::authorizeApiRequest(
							 auth, testRoutes(), request, response, source,
							 identity, mutationSources, mutations) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 429 &&
							 response.get_header_value("Retry-After") == "60",
						 "API requests exceeding the configured identity limit "
						 "should be rate limited");

	HttpApi::RateLimiter mutationIdentity(20, std::chrono::minutes(1));
	request				= requestWithSchema("POST", "/api/v1/rules");
	request.remote_addr = "192.0.2.56";
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(
		HttpApi::authorizeApiRequest(auth, testRoutes(), request, response,
									 source, mutationIdentity, mutationSources,
									 mutations) ==
			httplib::Server::HandlerResponse::Unhandled,
		"the first firewall mutation should pass its configured limit");
	response = httplib::Response{};
	TestSupport::require(
		HttpApi::authorizeApiRequest(auth, testRoutes(), request, response,
									 source, mutationIdentity, mutationSources,
									 mutations) ==
				httplib::Server::HandlerResponse::Handled &&
			response.status == 429,
		"firewall mutations exceeding their separate limit should be rejected");

	HttpApi::RateLimiter sourceMutation(1, std::chrono::minutes(1));
	HttpApi::RateLimiter identityMutation(20, std::chrono::minutes(1));
	HttpApi::RateLimiter apiIdentity(20, std::chrono::minutes(1));
	request				= requestWithSchema("POST", "/api/v1/rules");
	request.remote_addr = "192.0.2.61";
	request.set_header("Authorization", "Bearer operator-token");
	response					   = httplib::Response{};
	const auto firstSourceMutation = HttpApi::authorizeApiRequest(
		auth, testRoutes(), request, response, source, apiIdentity,
		sourceMutation, identityMutation);
	TestSupport::require(
		firstSourceMutation == httplib::Server::HandlerResponse::Unhandled,
		"the first mutation from a source should pass its source-IP limit; "
		"status=" +
			std::to_string(response.status) + " handler=" +
			std::to_string(static_cast<int>(firstSourceMutation)) +
			" body=" + response.body);
	auth.second_operator = true;
	request				 = requestWithSchema("POST", "/api/v1/rules");
	request.remote_addr	 = "192.0.2.61";
	request.set_header("Authorization", "Bearer operator-token");
	response = httplib::Response{};
	TestSupport::require(HttpApi::authorizeApiRequest(
							 auth, testRoutes(), request, response, source,
							 apiIdentity, sourceMutation, identityMutation) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 429,
						 "mutations by separate identities from one source "
						 "should share the IP limit");
}

void rejectsInvalidSessionsAndReportsStorageFailures() {
	MockAuthProvider auth;
	auto			 request = requestWithSchema("GET", "/api/v1/logs");
	request.set_header("Authorization", "Basic invalid");
	httplib::Response response;
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 401,
						 "non-Bearer credentials should be rejected");

	request.set_header("Authorization", "Bearer unknown-token");
	response = httplib::Response{};
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 401,
						 "unknown bearer sessions should be rejected");

	auth.storage_failure = true;
	request				 = requestWithSchema("GET", "/api/v1/logs");
	request.set_header("Authorization", "Bearer admin-token");
	response = httplib::Response{};
	TestSupport::require(authorize(auth, request, response) ==
								 httplib::Server::HandlerResponse::Handled &&
							 response.status == 500,
						 "authentication storage errors should fail closed");
}

void supportsLoginAndLogoutHandlers() {
	MockAuthProvider	 auth;
	HttpApi::RateLimiter limiter(5, std::chrono::minutes(5));
	httplib::Request request = requestWithSchema("POST", "/api/v1/auth/login");
	request.body = R"({"username":"admin","password":"correct test password"})";
	request.remote_addr = "192.0.2.10";
	httplib::Response response;
	HttpApi::login(auth, limiter, request, response);
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

void supportsAccountLifecycleHandlers() {
	MockAuthProvider  auth;
	httplib::Request  request;
	httplib::Response response;

	request.body = R"({"username":"operator","role":"operator"})";
	HttpApi::createAccount(auth, request, response);
	TestSupport::require(response.status == 201,
						 "account creation should return HTTP 201");
	auto payload = nlohmann::json::parse(response.body);
	TestSupport::require(payload["account"]["id"] == "new-account-id" &&
							 payload["account"]["setup_pending"] == true &&
							 payload["setup_token"] == "setup-token",
						 "account creation should return pending account "
						 "metadata and its token");

	response = httplib::Response{};
	request.body =
		R"({"username":"operator","role":"operator","unexpected":true})";
	HttpApi::createAccount(auth, request, response);
	TestSupport::require(response.status == 400,
						 "account creation should reject unknown fields");

	request.body.clear();
	response = httplib::Response{};
	HttpApi::getAccounts(auth, request, response);
	payload = nlohmann::json::parse(response.body);
	TestSupport::require(payload["accounts"].size() == 1 &&
							 payload["accounts"][0]["role"] == "operator",
						 "account listing should return account metadata");

	request.body = R"({"id":"account-id","role":"administrator"})";
	response	 = httplib::Response{};
	HttpApi::updateAccount(auth, request, response);
	payload = nlohmann::json::parse(response.body);
	TestSupport::require(
		response.status == 200 && payload["account"]["role"] == "administrator",
		"account updates should return updated metadata; status=" +
			std::to_string(response.status) + " body=" + response.body);

	request.body = R"({"id":"account-id"})";
	response	 = httplib::Response{};
	HttpApi::disableAccount(auth, request, response);
	TestSupport::require(
		response.status == 204 && auth.disabled_account_id == "account-id",
		"account disablement should return HTTP 204 and call the provider");

	request.body = R"({"id":"account-id"})";
	response	 = httplib::Response{};
	HttpApi::issueAccountSetupToken(auth, request, response);
	payload = nlohmann::json::parse(response.body);
	TestSupport::require(
		response.status == 200 && payload["setup_token"] == "replacement-token",
		"setup-token issuance should return the one-time token");

	request.body = "{\"setup_token\":\"" + std::string(64, 'a') +
				   "\",\"password\":\"a sufficiently long password\"}";
	response = httplib::Response{};
	HttpApi::completeAccountSetup(auth, request, response);
	TestSupport::require(response.status == 204,
						 "valid account setup should return HTTP 204");
}

void limitsFailedLoginAttemptsPerSource() {
	MockAuthProvider	 auth;
	HttpApi::RateLimiter limiter(2, std::chrono::minutes(5));
	httplib::Request request = requestWithSchema("POST", "/api/v1/auth/login");
	request.body = R"({"username":"admin","password":"incorrect password"})";
	request.remote_addr = "192.0.2.20";
	httplib::Response response;
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"first failed login should return invalid credentials");
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"second failed login should return invalid credentials");
	response = httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 429 &&
			response.get_header_value("Retry-After") == "300",
		"further login attempts should be rate limited with Retry-After");

	request.remote_addr = "192.0.2.21";
	response			= httplib::Response{};
	HttpApi::login(auth, limiter, request, response);
	TestSupport::require(
		response.status == 401,
		"failed attempts should be tracked per source address");
}
} // namespace

void runHttpAuthenticationTests() {
	healthLoginAndSetupAreTheOnlyPublicRoutes();
	protectsAllOtherRoutesByDefault();
	restrictsFirewallMutationsToElevatedRoles();
	restrictsAccountManagementToAdministrators();
	rejectsUnregisteredRoutesAfterAuthentication();
	rejectsDuplicateRoutePolicies();
	boundsTrackedRateLimitKeys();
	limitsApiRequestsAndFirewallMutations();
	rejectsInvalidSessionsAndReportsStorageFailures();
	supportsLoginAndLogoutHandlers();
	supportsAccountLifecycleHandlers();
	limitsFailedLoginAttemptsPerSource();
}
