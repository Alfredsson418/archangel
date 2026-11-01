#include "../src/firewall/nft_statistics.hpp"
#include "test_support.hpp"

#include <stdexcept>
#include <string>

namespace {
void parsesNftablesStatistics() {
	const FirewallStatistics statistics = statisticsFromNftRuleset(R"({
		"nftables": [
			{"table": {"family": "inet", "name": "filter"}},
			{"chain": {"family": "inet", "table": "filter", "name": "input"}},
			{"rule": {"family": "inet", "expr": [
				{"match": {"left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
				{"accept": null}
			]}},
			{"rule": {"family": "ip6", "expr": [
				{"match": {"left": {"meta": {"key": "l4proto"}}, "right": "udp"}},
				{"drop": null}
			]}},
			{"metainfo": {"version": "1"}}
		]
	})");

	TestSupport::require(statistics.total_tables == 1, "table count mismatch");
	TestSupport::require(statistics.total_chains == 1, "chain count mismatch");
	TestSupport::require(statistics.total_rules == 2, "rule count mismatch");
	TestSupport::require(statistics.rules_by_family.at("inet") == 1,
						 "inet family count mismatch");
	TestSupport::require(statistics.rules_by_family.at("ip6") == 1,
						 "ip6 family count mismatch");
	TestSupport::require(statistics.rules_by_protocol.at("tcp") == 1,
						 "tcp protocol count mismatch");
	TestSupport::require(statistics.rules_by_protocol.at("udp") == 1,
						 "udp protocol count mismatch");
	TestSupport::require(statistics.rules_by_verdict.at("accept") == 1,
						 "accept verdict count mismatch");
	TestSupport::require(statistics.rules_by_verdict.at("drop") == 1,
						 "drop verdict count mismatch");
}

void rejectsInvalidRulesetShapes() {
	TestSupport::requireThrows<std::runtime_error>(
		[] { statisticsFromNftRuleset(R"({"rules": []})"); },
		"ruleset missing nftables array should fail");
	TestSupport::requireThrows<std::exception>(
		[] { statisticsFromNftRuleset("{invalid"); },
		"malformed JSON should fail");
}
} // namespace

void runNftStatisticsTests() {
	parsesNftablesStatistics();
	rejectsInvalidRulesetShapes();
}
