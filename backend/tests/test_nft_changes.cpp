#include "../src/firewall/providers/nft_changes.hpp"
#include "firewall/bundle.hpp"
#include "test_support.hpp"
#include "json/json.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace {
using nlohmann::json;

const char *const LISTING = R"({"nftables":[
	{"metainfo":{"version":"1.1.6","json_schema_version":1}},
	{"table":{"family":"inet","name":"filter","handle":1}},
	{"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
	{"chain":{"family":"inet","table":"filter","name":"other","handle":2}},
	{"rule":{"family":"inet","table":"filter","chain":"input","handle":3,"expr":[{"counter":{"packets":1,"bytes":2}},{"accept":null}]}},
	{"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"comment":"archangel-managed","expr":[{"drop":null}]}}
]})";

std::string revisionOf(const std::string &listing, const std::string &chain) {
	for (const auto &revision : Firewall::Detail::chainRevisions(listing)) {
		if (revision.chain == chain) {
			return revision.revision;
		}
	}
	throw std::runtime_error("chain not found: " + chain);
}

std::string replaced(std::string listing, const std::string &from,
					 const std::string &to) {
	const std::size_t position = listing.find(from);
	TestSupport::require(position != std::string::npos,
						 "fixture should contain " + from);
	return listing.replace(position, from.size(), to);
}

Firewall::RuleSpec tcpRule(std::uint16_t port) {
	Firewall::RuleSpec rule;
	rule.family			  = "inet";
	rule.table			  = "filter";
	rule.chain			  = "input";
	rule.protocol		  = "tcp";
	rule.destination_port = port;
	rule.action			  = "accept";
	return rule;
}

Firewall::ChangeSet changeSet(std::vector<Firewall::Change> changes) {
	Firewall::ChangeSet set;
	set.expected = {
		{"inet", "filter", "input", revisionOf(LISTING, "input")}
	};
	set.changes = std::move(changes);
	return set;
}

void revisionsFollowRulesButNotTraffic() {
	const std::string input = revisionOf(LISTING, "input");
	TestSupport::require(input != revisionOf(LISTING, "other"),
						 "chains should have their own revisions");
	TestSupport::require(
		revisionOf(replaced(LISTING, R"("packets":1,"bytes":2)",
							R"("packets":99,"bytes":999)"),
				   "input") == input,
		"counter values must not change a revision");
	TestSupport::require(
		revisionOf(replaced(LISTING, R"({"drop":null})", R"({"accept":null})"),
				   "input") != input,
		"a changed rule must change the revision");
	TestSupport::require(revisionOf(replaced(LISTING, R"("handle":4)",
											 R"("handle":9)"),
									"input") != input,
						 "a changed handle must change the revision");
	TestSupport::require(
		revisionOf(
			replaced(LISTING, R"("policy":"accept")", R"("policy":"drop")"),
			"input") != input,
		"a changed policy must change the revision");
	TestSupport::require(
		revisionOf(replaced(LISTING, R"("handle":3,)", R"("handle":3,"comment":"x",)"),
				   "other") == revisionOf(LISTING, "other"),
		"a change in one chain must not affect another");
}

void refusesChainsThatChangedOrWereNotReviewed() {
	const auto set = changeSet({Firewall::AddRuleChange{tcpRule(22)}});
	Firewall::Detail::requireCurrentRevisions(LISTING, set);

	TestSupport::requireThrows<Firewall::ChangeConflictError>(
		[&] {
			Firewall::Detail::requireCurrentRevisions(
				replaced(LISTING, R"({"drop":null})", R"({"accept":null})"), set);
		},
		"a changed chain should conflict");

	auto missing	 = set;
	missing.expected = {};
	TestSupport::requireThrows<Firewall::InvalidRuleError>(
		[&] { Firewall::Detail::requireCurrentRevisions(LISTING, missing); },
		"an unreviewed chain should be refused");

	auto otherChain							   = set;
	std::get<Firewall::AddRuleChange>(otherChain.changes[0]).rule.chain = "gone";
	otherChain.expected = {
		{"inet", "filter", "gone", "x"}
	};
	TestSupport::requireThrows<Firewall::ChangeConflictError>(
		[&] { Firewall::Detail::requireCurrentRevisions(LISTING, otherChain); },
		"a chain that no longer exists should conflict");
}

void buildsOneTransactionInOrder() {
	const auto set =
		changeSet({Firewall::AddRuleChange{tcpRule(22)},
				   Firewall::DeleteRuleChange{"inet", "filter", "input", 3},
				   Firewall::AddRuleChange{tcpRule(23)}});
	const json commands = json::parse(Firewall::Detail::buildTransaction(
		LISTING, set, set.changes.size()))["nftables"];

	TestSupport::require(commands.size() == 3, "each change is one command");
	TestSupport::require(commands[0]["add"]["rule"]["comment"] ==
							 Firewall::ARCHANGEL_RULE_COMMENT,
						 "new rules should be marked as managed");
	TestSupport::require(commands[1]["delete"]["rule"]["handle"] == 3,
						 "delete should use the handle");
	TestSupport::require(commands[2]["add"]["rule"]["expr"][1]["match"]
							 ["right"] == 23,
						 "changes should keep their order");

	const json firstOnly = json::parse(
		Firewall::Detail::buildTransaction(LISTING, set, 1))["nftables"];
	TestSupport::require(firstOnly.size() == 1,
						 "a partial build should stop at the count");
}

void replacesInPlaceKeepingTheComment() {
	Firewall::RuleSpec rule = tcpRule(22);
	const auto		   set	= changeSet({Firewall::ReplaceRuleChange{rule, 4},
										 Firewall::ReplaceRuleChange{rule, 3}});
	const json		   commands = json::parse(Firewall::Detail::buildTransaction(
		LISTING, set, set.changes.size()))["nftables"];

	const json &managed = commands[0]["replace"]["rule"];
	TestSupport::require(managed["handle"] == 4,
						 "replace should target the handle");
	TestSupport::require(managed["comment"] == Firewall::ARCHANGEL_RULE_COMMENT,
						 "a managed rule should stay managed");
	TestSupport::require(managed["expr"][1]["match"]["right"] == 22,
						 "replace should carry the new statements");
	TestSupport::require(!commands[1]["replace"]["rule"].contains("comment"),
						 "an unmanaged rule should stay unmanaged");

	auto otherChain = changeSet({Firewall::ReplaceRuleChange{rule, 99}});
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] { Firewall::Detail::buildTransaction(LISTING, otherChain, 1); },
		"replacing a missing rule should be rejected");

	Firewall::RuleSpec invalid = tcpRule(22);
	invalid.source_address	   = "192.168.1.5/24";
	auto badRule = changeSet({Firewall::ReplaceRuleChange{invalid, 3}});
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] { Firewall::Detail::buildTransaction(LISTING, badRule, 1); },
		"an invalid replacement should be rejected");
}

void identifiesTheChangeItRejects() {
	Firewall::RuleSpec invalid = tcpRule(22);
	invalid.source_address	   = "192.168.1.5/24";
	const auto invalidRule	   = changeSet({Firewall::AddRuleChange{tcpRule(1)},
											Firewall::AddRuleChange{invalid}});
	const auto missingRule	   = changeSet(
		{Firewall::AddRuleChange{tcpRule(1)},
			 Firewall::DeleteRuleChange{"inet", "filter", "input", 3},
			 Firewall::DeleteRuleChange{"inet", "filter", "input", 99}});
	for (const auto &[set, index] :
		 {std::pair{invalidRule, std::size_t{1}}, std::pair{missingRule, std::size_t{2}}}) {
		try {
			Firewall::Detail::buildTransaction(LISTING, set, set.changes.size());
			throw std::logic_error("invalid change set should be rejected");
		} catch (const Firewall::ChangeRejectedError &error) {
			TestSupport::require(error.index() == index,
								 "rejection should identify the change");
		}
	}
}

void rejectsMalformedListings() {
	for (const std::string listing : {"not json", "{}", R"({"nftables":{}})"}) {
		TestSupport::requireThrows<std::runtime_error>(
			[&] { Firewall::Detail::chainRevisions(listing); },
			"malformed listing should fail");
	}
}
} // namespace

void runNftChangesTests() {
	revisionsFollowRulesButNotTraffic();
	refusesChainsThatChangedOrWereNotReviewed();
	buildsOneTransactionInOrder();
	replacesInPlaceKeepingTheComment();
	identifiesTheChangeItRejects();
	rejectsMalformedListings();
}
