#include "config/app_config.hpp"
#include "http/api/rules.hpp"
#include "test_support.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace {
class MockFirewall final : public Firewall::Backend {
  public:
	std::string listRules() override {
		if (fail_list) {
			throw std::runtime_error("private backend detail");
		}
		return R"({"nftables":[]})";
	}

	Firewall::Statistics getStatistics() override { return {}; }

	void addRule(const Firewall::RuleSpec &rule) override {
		if (reject_rules) {
			throw Firewall::InvalidRuleError("protocol must be tcp or udp");
		}
		++add_calls;
		added_rule = rule;
	}

	void deleteRule(const std::string &family, const std::string &table,
					const std::string &chain, std::uint64_t handle) override {
		if (reject_rules) {
			throw Firewall::InvalidRuleError("table is invalid");
		}
		++delete_calls;
		deleted_family = family;
		deleted_table  = table;
		deleted_chain  = chain;
		deleted_handle = handle;
	}

	std::vector<Firewall::ChainRevision> chainRevisions() override {
		return {
			{"inet", "filter", "input", "abc"}
		};
	}

	void checkChanges(const Firewall::ChangeSet &changes) override {
		++check_calls;
		received_changes = changes;
		throwConfiguredError();
	}

	void applyChanges(const Firewall::ChangeSet &changes) override {
		++apply_calls;
		received_changes = changes;
		throwConfiguredError();
	}

	void throwConfiguredError() const {
		if (conflict) {
			throw Firewall::ChangeConflictError("A chain has changed");
		}
		if (reject_change) {
			throw Firewall::ChangeRejectedError(2, "The firewall rejected this");
		}
		if (fail_apply) {
			throw std::runtime_error("private backend detail");
		}
	}

	int					check_calls	  = 0;
	int					apply_calls	  = 0;
	bool				conflict	  = false;
	bool				reject_change = false;
	bool				fail_apply	  = false;
	Firewall::ChangeSet received_changes;
	int				   add_calls	= 0;
	int				   delete_calls = 0;
	bool			   fail_list	= false;
	bool			   reject_rules = false;
	Firewall::RuleSpec added_rule;
	std::string		   deleted_family;
	std::string		   deleted_table;
	std::string		   deleted_chain;
	std::uint64_t	   deleted_handle = 0;
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

	Http::createRule(firewall, request, response);

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

	Http::createRule(firewall, request, response);

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
		Http::createRule(firewall, requestWithBody(body), response);

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

void forwardsTheFullRuleModel() {
	MockFirewall		   firewall;
	const httplib::Request request = requestWithBody(
		R"({"family":"inet","table":"filter","chain":"input","protocol":"udp","source_address":"192.0.2.0/24","destination_port":53,"destination_port_end":60,"input_interface":"eth0","output_interface":"lo","connection_states":["new","established"],"action":"reject"})");
	httplib::Response response;

	Http::createRule(firewall, request, response);

	TestSupport::require(response.status == 201,
						 "valid full rule should return 201");
	const Firewall::RuleSpec &rule = firewall.added_rule;
	TestSupport::require(rule.source_address ==
							 std::optional<std::string>("192.0.2.0/24"),
						 "subnet should be forwarded");
	TestSupport::require(rule.destination_port == 53 &&
							 rule.destination_port_end == 60,
						 "port range should be forwarded");
	TestSupport::require(
		rule.input_interface == std::optional<std::string>("eth0") &&
			rule.output_interface == std::optional<std::string>("lo"),
		"interfaces should be forwarded");
	TestSupport::require(rule.connection_states ==
							 std::vector<std::string>{"new", "established"},
						 "connection states should be forwarded");
}

void acceptsARuleWithoutAProtocol() {
	MockFirewall	  firewall;
	httplib::Response response;
	Http::createRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","connection_states":["established","related"],"action":"accept"})"),
		response);

	TestSupport::require(response.status == 201,
						 "a rule without a protocol should be accepted");
	TestSupport::require(!firewall.added_rule.protocol,
						 "an absent protocol should stay absent");
}

void rejectsUnknownFieldsBeforeBackendMutation() {
	// A field the API ignored could leave a broader rule than was requested.
	MockFirewall	  firewall;
	httplib::Response response;
	Http::createRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":22,"action":"accept","source_ports":[1]})"),
		response);
	TestSupport::require(response.status == 400,
						 "unknown rule field should return 400");
	TestSupport::require(firewall.add_calls == 0,
						 "unknown rule field must not reach the backend");

	response = {};
	Http::deleteRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","handle":1,"expected":{}})"),
		response);
	TestSupport::require(response.status == 400,
						 "unknown delete field should return 400");
	TestSupport::require(firewall.delete_calls == 0,
						 "unknown delete field must not reach the backend");
}

void rejectsInvalidNewRuleFieldTypes() {
	for (
		const std::string body :
		{R"({"family":"inet","table":"t","chain":"c","action":"accept","connection_states":"new"})",
		 R"({"family":"inet","table":"t","chain":"c","action":"accept","connection_states":[1]})",
		 R"({"family":"inet","table":"t","chain":"c","action":"accept","connection_states":["new","new","new","new","new"]})",
		 R"({"family":"inet","table":"t","chain":"c","action":"accept","input_interface":1})",
		 R"({"family":"inet","table":"t","chain":"c","action":"accept","protocol":"tcp","destination_port":1,"destination_port_end":70000})",
		 R"({"family":"inet","table":"t","chain":"c","action":"accept","protocol":7})"}) {
		MockFirewall	  firewall;
		httplib::Response response;
		Http::createRule(firewall, requestWithBody(body), response);
		TestSupport::require(response.status == 400,
							 "invalid new field should return 400");
		TestSupport::require(firewall.add_calls == 0,
							 "invalid new field must not reach the backend");
	}
}

const char *const VALID_CHANGES = R"({
	"expected_revisions":[{"family":"inet","table":"filter","chain":"input","revision":"abc"}],
	"changes":[
		{"type":"add_rule","rule":{"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":22,"action":"accept"}},
		{"type":"delete_rule","family":"inet","table":"filter","chain":"input","handle":7}
	]})";

void appliesAndChecksAChangeList() {
	MockFirewall	  firewall;
	httplib::Response response;
	Http::applyFirewallChanges(firewall, requestWithBody(VALID_CHANGES),
							   response);

	TestSupport::require(firewall.apply_calls == 1,
						 "change list should reach the backend once");
	TestSupport::require(response.body == R"({"changes":2,"status":"applied"})",
						 "apply should report the applied count");
	const Firewall::ChangeSet &changes = firewall.received_changes;
	TestSupport::require(changes.expected.size() == 1 &&
							 changes.expected[0].revision == "abc",
						 "expected revisions should be forwarded");
	TestSupport::require(changes.changes.size() == 2,
						 "every change should be forwarded");
	TestSupport::require(std::get<Firewall::AddRuleChange>(changes.changes[0])
								 .rule.destination_port == 22,
						 "add should carry its rule");
	TestSupport::require(
		std::get<Firewall::DeleteRuleChange>(changes.changes[1]).handle == 7,
		"delete should carry its handle");

	MockFirewall	  checking;
	httplib::Response checked;
	Http::checkFirewallChanges(checking, requestWithBody(VALID_CHANGES),
							   checked);
	TestSupport::require(checking.check_calls == 1 && checking.apply_calls == 0,
						 "check must not apply");
	TestSupport::require(checked.body == R"({"changes":2,"status":"valid"})",
						 "check should report validity");
}

void parsesReplacementChanges() {
	MockFirewall	  firewall;
	httplib::Response response;
	Http::applyFirewallChanges(
		firewall,
		requestWithBody(
			R"({"expected_revisions":[],"changes":[{"type":"replace_rule","handle":9,"rule":{"family":"inet","table":"filter","chain":"input","protocol":"tcp","destination_port":22,"action":"drop"}}]})"),
		response);
	TestSupport::require(firewall.apply_calls == 1,
						 "valid replacement should be accepted");
	const auto &change = std::get<Firewall::ReplaceRuleChange>(
		firewall.received_changes.changes[0]);
	TestSupport::require(change.handle == 9 && change.rule.action == "drop",
						 "replacement should carry its handle and rule");

	for (const std::string &body : std::vector<std::string>{
			 R"({"expected_revisions":[],"changes":[{"type":"replace_rule","rule":{"family":"inet","table":"f","chain":"c","action":"drop"}}]})",
			 R"({"expected_revisions":[],"changes":[{"type":"replace_rule","handle":9}]})",
			 R"({"expected_revisions":[],"changes":[{"type":"replace_rule","handle":0,"rule":{"family":"inet","table":"f","chain":"c","action":"drop"}}]})",
			 R"({"expected_revisions":[],"changes":[{"type":"replace_rule","handle":9,"extra":1,"rule":{"family":"inet","table":"f","chain":"c","action":"drop"}}]})"}) {
		MockFirewall	  rejecting;
		httplib::Response rejected;
		Http::applyFirewallChanges(rejecting, requestWithBody(body), rejected);
		TestSupport::require(rejected.status == 400 &&
								 rejecting.apply_calls == 0,
							 "malformed replacement should return 400: " + body);
	}
}

void mapsChangeListFailuresToSafeResponses() {
	MockFirewall conflicted;
	conflicted.conflict = true;
	httplib::Response response;
	Http::applyFirewallChanges(conflicted, requestWithBody(VALID_CHANGES),
							   response);
	TestSupport::require(response.status == 409,
						 "a changed chain should return 409");
	TestSupport::require(response.body.find("firewall_changed") !=
							 std::string::npos,
						 "conflict should use a stable code");

	MockFirewall rejecting;
	rejecting.reject_change = true;
	response				= {};
	Http::applyFirewallChanges(rejecting, requestWithBody(VALID_CHANGES),
							   response);
	TestSupport::require(response.status == 422,
						 "a rejected change should return 422");
	TestSupport::require(response.body.find("\"change_index\":2") !=
							 std::string::npos,
						 "rejection should identify the change");

	MockFirewall failing;
	failing.fail_apply = true;
	response		   = {};
	Http::applyFirewallChanges(failing, requestWithBody(VALID_CHANGES),
							   response);
	TestSupport::require(response.status == 500,
						 "an unexpected failure should return 500");
	TestSupport::require(response.body.find("private backend detail") ==
							 std::string::npos,
						 "failure detail must not be exposed");
}

void rejectsMalformedChangeListsBeforeBackendMutation() {
	const std::string expected = R"("expected_revisions":[],)";
	for (const std::string &body : std::vector<std::string>{
			 "[]",
			 "{invalid",
			 "{}",
			 R"({"changes":[{"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":1}]})",
			 "{" + expected + R"("changes":[]})",
			 "{" + expected + R"("changes":{}})",
			 "{" + expected + R"("changes":[1]})",
			 "{" + expected + R"("changes":[{"type":"flush_ruleset"}]})",
			 "{" + expected + R"("changes":[{"type":"add_rule"}]})",
			 "{" + expected +
				 R"("changes":[{"type":"add_rule","rule":{"family":"inet","table":"f","chain":"c","action":"accept","raw":"x"}}]})",
			 "{" + expected +
				 R"("changes":[{"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":0}]})",
			 "{" + expected +
				 R"("changes":[{"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":1,"extra":1}]})",
			 R"({"expected_revisions":[1],"changes":[{"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":1}]})",
			 R"({"expected_revisions":[],"changes":[{"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":1}],"dry_run":true})"}) {
		MockFirewall	  firewall;
		httplib::Response response;
		Http::applyFirewallChanges(firewall, requestWithBody(body), response);
		TestSupport::require(response.status == 400,
							 "malformed change list should return 400: " + body);
		TestSupport::require(firewall.apply_calls == 0,
							 "malformed change list must not reach the backend");
	}
}

void boundsChangeLists() {
	const std::string change =
		R"({"type":"delete_rule","family":"inet","table":"f","chain":"c","handle":1})";
	const auto listOf = [&](std::size_t count) {
		std::string body = R"({"expected_revisions":[],"changes":[)";
		for (std::size_t index = 0; index < count; ++index) {
			body += (index == 0 ? "" : ",") + change;
		}
		return body + "]}";
	};

	MockFirewall	  firewall;
	httplib::Response response;
	Http::applyFirewallChanges(
		firewall, requestWithBody(listOf(Config::Limits::MAX_FIREWALL_CHANGES)),
		response);
	TestSupport::require(firewall.apply_calls == 1,
						 "a list at the limit should be accepted");

	response = {};
	Http::applyFirewallChanges(
		firewall,
		requestWithBody(listOf(Config::Limits::MAX_FIREWALL_CHANGES + 1)),
		response);
	TestSupport::require(response.status == 400 && firewall.apply_calls == 1,
						 "a list over the limit should be rejected");

	response = {};
	Http::applyFirewallChanges(
		firewall,
		requestWithBody(
			std::string(Config::Limits::MAX_FIREWALL_CHANGES_BYTES + 1, ' ')),
		response);
	TestSupport::require(response.status == 400 && firewall.apply_calls == 1,
						 "an oversized body should be rejected");
}

void reportsChainRevisions() {
	MockFirewall	  firewall;
	httplib::Response response;
	Http::getChainRevisions(firewall, httplib::Request{}, response);
	TestSupport::require(
		response.body ==
			R"({"chains":[{"chain":"input","family":"inet","revision":"abc","table":"filter"}]})",
		"revisions should use the expected JSON shape");
}

void deletesRuleByPositiveHandle() {
	MockFirewall	  firewall;
	httplib::Response response;
	response.status = 200;
	Http::deleteRule(
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
		Http::deleteRule(firewall, requestWithBody(body), response);

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
		Http::deleteRule(firewall, requestWithBody(body), response);

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

	Http::getRules(firewall, httplib::Request{}, response);

	TestSupport::require(response.status == 500,
						 "backend failure should return 500");
	TestSupport::require(response.body.find("Firewall operation failed") !=
							 std::string::npos,
						 "backend error should have a safe client message");
	TestSupport::require(response.body.find("private backend detail") ==
							 std::string::npos,
						 "backend exception detail must not be exposed");
}
void reportsBackendRuleRejectionsAsClientErrors() {
	MockFirewall firewall;
	firewall.reject_rules = true;
	httplib::Response created;
	Http::createRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","protocol":"tcp","action":"accept"})"),
		created);
	TestSupport::require(
		created.status == 400 &&
			created.body.find(R"("code":"invalid_request")") !=
				std::string::npos &&
			created.body.find("protocol must be tcp or udp") !=
				std::string::npos,
		"backend rule rejections should return 400 with the backend reason");
	httplib::Response deleted;
	Http::deleteRule(
		firewall,
		requestWithBody(
			R"({"family":"inet","table":"filter","chain":"input","handle":4})"),
		deleted);
	TestSupport::require(deleted.status == 400,
						 "backend target rejections should return 400");
}
} // namespace

void runRulesApiTests() {
	reportsBackendRuleRejectionsAsClientErrors();
	createsStructuredRule();
	forwardsTheFullRuleModel();
	acceptsARuleWithoutAProtocol();
	rejectsUnknownFieldsBeforeBackendMutation();
	rejectsInvalidNewRuleFieldTypes();
	acceptsMaximumDestinationPortAndNullOptionalAddresses();
	rejectsInvalidRuleRequestsBeforeBackendMutation();
	appliesAndChecksAChangeList();
	parsesReplacementChanges();
	mapsChangeListFailuresToSafeResponses();
	rejectsMalformedChangeListsBeforeBackendMutation();
	boundsChangeLists();
	reportsChainRevisions();
	deletesRuleByPositiveHandle();
	rejectsInvalidDeleteHandlesBeforeBackendMutation();
	rejectsDeleteRequestsMissingRequiredFields();
	hidesBackendFailureDetails();
}
