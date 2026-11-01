#include "../include/http/api/rules.hpp"
#include "test_support.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

namespace {
class MockFirewall final : public Firewall {
  public:
	std::string listRules() override {
		if (fail_list) {
			throw std::runtime_error("private backend detail");
		}
		return R"({"nftables":[]})";
	}

	FirewallStatistics getStatistics() override { return {}; }

	void addRule(const RuleSpec &rule) override {
		++add_calls;
		added_rule = rule;
	}

	void deleteRule(const std::string &family, const std::string &table,
					const std::string &chain, std::uint64_t handle) override {
		++delete_calls;
		deleted_family = family;
		deleted_table  = table;
		deleted_chain  = chain;
		deleted_handle = handle;
	}

	int			  add_calls	   = 0;
	int			  delete_calls = 0;
	bool		  fail_list	   = false;
	RuleSpec	  added_rule;
	std::string	  deleted_family;
	std::string	  deleted_table;
	std::string	  deleted_chain;
	std::uint64_t deleted_handle = 0;
};

httplib::Request requestWithBody(const std::string &body) {
	httplib::Request request;
	request.body = body;
	return request;
}

void createsStructuredRule() {
	MockFirewall		   firewall;
	const httplib::Request request = requestWithBody(
		R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":443,"action":"accept","source_address":"192.0.2.1"})");
	httplib::Response response;

	HttpApi::createRule(firewall, request, response);

	TestSupport::require(response.status == 201,
						 "valid rule should return 201");
	TestSupport::require(firewall.add_calls == 1,
						 "backend should receive one rule");
	TestSupport::require(firewall.added_rule.family == "inet",
						 "family should be forwarded");
	TestSupport::require(firewall.added_rule.destination_port == 443,
						 "destination port should be forwarded");
	TestSupport::require(firewall.added_rule.source_address ==
							 std::optional<std::string>("192.0.2.1"),
						 "source address should be forwarded");
	TestSupport::require(
		response.body == R"({"status":"created"})",
		"creation response should use the expected JSON shape");
}

void acceptsMaximumDestinationPortAndNullOptionalAddresses() {
	MockFirewall		   firewall;
	const httplib::Request request = requestWithBody(
		R"({"family":"ip","table":"filter","chain":"input","protocol":"udp","destination_port":65535,"action":"drop","source_address":null,"destination_address":null})");
	httplib::Response response;

	HttpApi::createRule(firewall, request, response);

	TestSupport::require(response.status == 201,
						 "valid maximum port should return 201");
	TestSupport::require(firewall.add_calls == 1,
						 "valid maximum port should reach backend");
	TestSupport::require(firewall.added_rule.destination_port == 65535,
						 "maximum destination port should be preserved");
	TestSupport::require(!firewall.added_rule.source_address &&
							 !firewall.added_rule.destination_address,
						 "null optional addresses should be treated as absent");
}

void rejectsInvalidRuleRequestsBeforeBackendMutation() {
	for (
		const std::string body :
		{R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":0,"action":"accept"})",
		 R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":65536,"action":"accept"})",
		 R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":1.5,"action":"accept"})",
		 R"({"table":"filter","chain":"input","protocol":"tcp","action":"accept"})",
		 R"({"family":"inet","table":"","chain":"input","protocol":"tcp","action":"accept"})",
		 R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","action":"accept","source_address":7})",
		 "[]", "{invalid"}) {
		MockFirewall	  firewall;
		httplib::Response response;
		HttpApi::createRule(firewall, requestWithBody(body), response);

		TestSupport::require(response.status == 400,
							 "invalid rule request should return 400");
		TestSupport::require(firewall.add_calls == 0,
							 "invalid rule must not reach the backend");
		TestSupport::require(
			response.body.find("\"code\":\"invalid_request\"") !=
				std::string::npos,
			"invalid request should return the standard error shape");
	}
}

void deletesRuleByPositiveHandle() {
	MockFirewall	  firewall;
	httplib::Response response;
	response.status = 200;
	HttpApi::deleteRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","handle":42})"),
		response);

	TestSupport::require(response.status == 200, "delete should return 200");
	TestSupport::require(firewall.delete_calls == 1,
						 "backend should receive one delete request");
	TestSupport::require(firewall.deleted_family == "inet" &&
							 firewall.deleted_table == "filter" &&
							 firewall.deleted_chain == "input" &&
							 firewall.deleted_handle == 42,
						 "delete fields should be forwarded");
	TestSupport::require(response.body == R"({"status":"deleted"})",
						 "delete response should use the expected JSON shape");
}

void rejectsInvalidDeleteHandlesBeforeBackendMutation() {
	for (
		const std::string body :
		{R"({"family":"inet","table":"filter","chain":"input","handle":0})",
		 R"({"family":"inet","table":"filter","chain":"input","handle":-1})",
		 R"({"family":"inet","table":"filter","chain":"input","handle":"42"})",
		 R"({"family":"inet","table":"filter","chain":"input","handle":1.5})"}) {
		MockFirewall	  firewall;
		httplib::Response response;
		HttpApi::deleteRule(firewall, requestWithBody(body), response);

		TestSupport::require(response.status == 400,
							 "invalid delete handle should return 400");
		TestSupport::require(firewall.delete_calls == 0,
							 "invalid delete must not reach the backend");
	}
}

void rejectsDeleteRequestsMissingRequiredFields() {
	for (const std::string body :
		 {R"({"table":"filter","chain":"input","handle":42})",
		  R"({"family":"inet","chain":"input","handle":42})",
		  R"({"family":"inet","table":"filter","handle":42})",
		  R"({"family":"inet","table":"filter","chain":"input"})"}) {
		MockFirewall	  firewall;
		httplib::Response response;
		HttpApi::deleteRule(firewall, requestWithBody(body), response);

		TestSupport::require(response.status == 400,
							 "missing delete fields should return 400");
		TestSupport::require(firewall.delete_calls == 0,
							 "incomplete delete must not reach the backend");
	}
}

void hidesBackendFailureDetails() {
	MockFirewall firewall;
	firewall.fail_list = true;
	httplib::Response response;

	HttpApi::getRules(firewall, httplib::Request{}, response);

	TestSupport::require(response.status == 500,
						 "backend failure should return 500");
	TestSupport::require(response.body.find("Firewall operation failed") !=
							 std::string::npos,
						 "backend error should have a safe client message");
	TestSupport::require(response.body.find("private backend detail") ==
							 std::string::npos,
						 "backend exception detail must not be exposed");
}
} // namespace

void runRulesApiTests() {
	createsStructuredRule();
	acceptsMaximumDestinationPortAndNullOptionalAddresses();
	rejectsInvalidRuleRequestsBeforeBackendMutation();
	deletesRuleByPositiveHandle();
	rejectsInvalidDeleteHandlesBeforeBackendMutation();
	rejectsDeleteRequestsMissingRequiredFields();
	hidesBackendFailureDetails();
}
