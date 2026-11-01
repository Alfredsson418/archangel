#include "../lib/json/json.hpp"
#include "../src/firewall/providers/nft_import.hpp"
#include "test_support.hpp"

#include <stdexcept>
#include <string>

namespace {
using Json = nlohmann::json;

const std::string activeRuleset = R"({
	"nftables": [
		{"table": {"family": "inet", "name": "filter"}},
		{"chain": {"family": "inet", "table": "filter", "name": "input"}},
		{"rule": {"family": "inet", "table": "filter", "chain": "input",
			"handle": 1, "expr": [{"accept": null}]}},
		{"rule": {"family": "inet", "table": "filter", "chain": "input",
			"handle": 2, "comment": "archangel-managed",
			"expr": [{"drop": null}]}}
	]
})";

const std::string replacementRules = R"([
	{"rule": {"family": "inet", "table": "filter", "chain": "input",
		"handle": 99, "comment": "archangel-managed",
		"expr": [{"reject": null}]}}
])";

void replacesOnlyMarkedRules() {
	const ArchangelRulesReplacement replacement =
		buildArchangelRulesReplacement(activeRuleset, replacementRules);
	const Json transaction = Json::parse(replacement.transaction);

	TestSupport::require(replacement.removed == 1,
						 "replacement should delete one marked rule");
	TestSupport::require(replacement.added == 1,
						 "replacement should add one marked rule");
	TestSupport::require(transaction["nftables"].size() == 2,
						 "transaction should contain one delete and one add");
	TestSupport::require(
		transaction["nftables"][0]["delete"]["rule"]["handle"] == 2,
		"transaction should delete the active marked rule by handle");
	TestSupport::require(transaction["nftables"][1]["add"]["rule"]["comment"] ==
							 "archangel-managed",
						 "transaction should add the marked replacement");
	TestSupport::require(
		!transaction["nftables"][0]["delete"]["rule"].contains("expr"),
		"delete should not include external rule contents");
}

void emptyReplacementDoesNotCreateATransactionWhenNothingIsManaged() {
	const ArchangelRulesReplacement replacement = buildArchangelRulesReplacement(
		R"({"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","handle":1,"expr":[{"accept":null}]}}]})",
		"[]");

	TestSupport::require(replacement.transaction.empty(),
						 "no managed rules should produce no nft transaction");
	TestSupport::require(replacement.removed == 0 && replacement.added == 0,
						 "empty replacement counts should be zero");
}

void rejectsUnmarkedReplacementRulesAndUnaddressableManagedRules() {
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			buildArchangelRulesReplacement(
				activeRuleset,
				R"([{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"accept":null}]}}])");
		},
		"unmarked incoming rules must not be managed replacements");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			buildArchangelRulesReplacement(
				R"({"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","comment":"archangel-managed","expr":[{"accept":null}]}}]})",
				"[]");
		},
		"marked active rules without handles must not be deleted");
}
} // namespace

void runNftImportTests() {
	replacesOnlyMarkedRules();
	emptyReplacementDoesNotCreateATransactionWhenNothingIsManaged();
	rejectsUnmarkedReplacementRulesAndUnaddressableManagedRules();
}
