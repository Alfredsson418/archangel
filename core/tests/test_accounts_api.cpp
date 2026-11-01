#include "http/api/accounts.hpp"
#include "http/api/auth.hpp"

#include "auth_test_support.hpp"
#include "test_support.hpp"

#include "json/json.hpp"

#include <string>

namespace {
using TestSupport::MockAuthProvider;
using TestSupport::requestWithSchema;

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
} // namespace

void runAccountsApiTests() { supportsAccountLifecycleHandlers(); }
