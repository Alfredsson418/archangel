#include "nft_statistics.hpp"
#include "../../lib/json/json.hpp"
#include <stdexcept>

FirewallStatistics statisticsFromNftRuleset(const std::string &rulesetJson) {
	using Json		   = nlohmann::json;
	const Json ruleset = Json::parse(rulesetJson);
	if (!ruleset.is_object() || !ruleset.contains("nftables") ||
		!ruleset["nftables"].is_array()) {
		throw std::runtime_error("Invalid nftables ruleset JSON");
	}

	FirewallStatistics statistics;
	// nftables JSON is a sequence of typed objects (tables, chains, rules, and
	// metadata); count each type independently before inspecting rule
	// expressions.
	for (const Json &entry : ruleset["nftables"]) {
		if (!entry.is_object()) {
			continue;
		}
		if (entry.contains("table")) {
			++statistics.total_tables;
		}
		if (entry.contains("chain")) {
			++statistics.total_chains;
		}
		if (!entry.contains("rule") || !entry["rule"].is_object()) {
			continue;
		}

		const Json &rule = entry["rule"];
		++statistics.total_rules;
		const std::string family = rule.value("family", "other");
		++statistics.rules_by_family[family];

		std::string protocol   = "other";
		std::string verdict	   = "other";
		const auto	expression = rule.find("expr");
		if (expression != rule.end() && expression->is_array()) {
			// Infer display statistics from the nested nftables expression
			// tree: verdicts are statement keys, while L4 protocol is a match
			// on meta.
			for (const Json &statement : *expression) {
				if (!statement.is_object()) {
					continue;
				}
				for (const char *candidate : {"accept", "drop", "reject"}) {
					if (statement.contains(candidate)) {
						verdict = candidate;
						break;
					}
				}

				const auto match = statement.find("match");
				if (match == statement.end() || !match->is_object()) {
					continue;
				}
				const auto left	 = match->find("left");
				const auto right = match->find("right");
				if (left == match->end() || !left->is_object() ||
					right == match->end() || !right->is_string()) {
					continue;
				}
				const auto meta = left->find("meta");
				if (meta != left->end() && meta->is_object() &&
					meta->value("key", std::string()) == "l4proto") {
					const std::string candidate = right->get<std::string>();
					if (candidate == "tcp" || candidate == "udp") {
						protocol = candidate;
					}
				}
			}
		}
		++statistics.rules_by_protocol[protocol];
		++statistics.rules_by_verdict[verdict];
	}

	return statistics;
}
