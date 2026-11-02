#include "../src/firewall/providers/nft_changes.hpp"
#include "firewall/bundle.hpp"
#include "test_support.hpp"
#include "json/json.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <variant>
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
	TestSupport::require(
		revisionOf(replaced(LISTING, R"("handle":4)", R"("handle":9)"),
				   "input") != input,
		"a changed handle must change the revision");
	TestSupport::require(revisionOf(replaced(LISTING, R"("policy":"accept")",
											 R"("policy":"drop")"),
									"input") != input,
						 "a changed policy must change the revision");
	TestSupport::require(revisionOf(replaced(LISTING, R"("handle":3,)",
											 R"("handle":3,"comment":"x",)"),
									"other") == revisionOf(LISTING, "other"),
						 "a change in one chain must not affect another");
}

void refusesChainsThatChangedOrWereNotReviewed() {
	const auto set = changeSet({
		Firewall::AddRuleChange{tcpRule(22), ""}
	});
	Firewall::Detail::requireCurrentRevisions(LISTING, set);

	TestSupport::requireThrows<Firewall::ChangeConflictError>(
		[&] {
			Firewall::Detail::requireCurrentRevisions(
				replaced(LISTING, R"({"drop":null})", R"({"accept":null})"),
				set);
		},
		"a changed chain should conflict");

	auto missing	 = set;
	missing.expected = {};
	TestSupport::requireThrows<Firewall::InvalidRuleError>(
		[&] { Firewall::Detail::requireCurrentRevisions(LISTING, missing); },
		"an unreviewed chain should be refused");

	auto otherChain = set;
	std::get<Firewall::AddRuleChange>(otherChain.changes[0]).rule.chain =
		"gone";
	otherChain.expected = {
		{"inet", "filter", "gone", "x"}
	   };
	TestSupport::requireThrows<Firewall::ChangeConflictError>(
		[&] { Firewall::Detail::requireCurrentRevisions(LISTING, otherChain); },
		"a chain that no longer exists should conflict");
}

void buildsOneTransactionInOrder() {
	const auto set		= changeSet({
		 Firewall::AddRuleChange{tcpRule(22), ""},
		 Firewall::DeleteRuleChange{"inet", "filter", "input", 3},
		 Firewall::AddRuleChange{tcpRule(23), ""}
	 });
	const json commands = json::parse(Firewall::Detail::buildTransaction(
		LISTING, set, set.changes.size()))["nftables"];

	TestSupport::require(commands.size() == 3, "each change is one command");
	TestSupport::require(commands[0]["add"]["rule"]["comment"] ==
							 Firewall::ARCHANGEL_RULE_COMMENT,
						 "new rules should be marked as managed");
	TestSupport::require(commands[1]["delete"]["rule"]["handle"] == 3,
						 "delete should use the handle");
	TestSupport::require(
		commands[2]["add"]["rule"]["expr"][1]["match"]["right"] == 23,
		"changes should keep their order");

	const json firstOnly = json::parse(
		Firewall::Detail::buildTransaction(LISTING, set, 1))["nftables"];
	TestSupport::require(firstOnly.size() == 1,
						 "a partial build should stop at the count");
}

void replacesInPlaceKeepingTheComment() {
	Firewall::RuleSpec rule = tcpRule(22);
	const auto		   set	= changeSet({
		 Firewall::ReplaceRuleChange{rule, 4},
		 Firewall::ReplaceRuleChange{rule, 3}
	 });
	const json commands		= json::parse(Firewall::Detail::buildTransaction(
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

	auto otherChain = changeSet({
		Firewall::ReplaceRuleChange{rule, 99}
	 });
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] { Firewall::Detail::buildTransaction(LISTING, otherChain, 1); },
		"replacing a missing rule should be rejected");

	Firewall::RuleSpec invalid = tcpRule(22);
	invalid.source_address	   = "192.168.1.5/24";
	auto badRule			   = changeSet({
		  Firewall::ReplaceRuleChange{invalid, 3}
	 });
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] { Firewall::Detail::buildTransaction(LISTING, badRule, 1); },
		"an invalid replacement should be rejected");
}

std::vector<json>
transaction(std::vector<Firewall::Change>		 changes,
			std::vector<Firewall::ChainRevision> expected = {}) {
	Firewall::ChangeSet set;
	set.expected = std::move(expected);
	set.changes	 = std::move(changes);
	return json::parse(Firewall::Detail::buildTransaction(
		LISTING, set, set.changes.size()))["nftables"]
		.get<std::vector<json>>();
}

template <typename Change>
void requireRejected(const Change &change, const std::string &message) {
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] { transaction({change}); }, message);
}

void reorderingRebuildsTheChainKeepingItsRules() {
	const auto commands = transaction({
		Firewall::SetRuleOrderChange{
									 "inet", "filter", "input", {std::uint64_t{4}, std::uint64_t{3}}}
	});
	TestSupport::require(commands.size() == 3,
						 "a reorder should flush and re-add every rule");
	TestSupport::require(commands[0]["flush"]["chain"]["name"] == "input",
						 "the chain should be flushed first");
	const json &first = commands[1]["add"]["rule"];
	TestSupport::require(first["expr"][0].contains("drop"),
						 "rules should follow the new order");
	TestSupport::require(first["comment"] == Firewall::ARCHANGEL_RULE_COMMENT,
						 "comments should be kept");
	TestSupport::require(!first.contains("handle"),
						 "re-added rules must not name their old handle");
	const json &second = commands[2]["add"]["rule"];
	TestSupport::require(second["expr"][0]["counter"]["packets"] == 1,
						 "counter values should be kept");
}

void reorderingPlacesNewRulesAndIncludesOtherChanges() {
	Firewall::AddRuleChange added{tcpRule(22), "new-1"};
	const auto				commands = transaction({
		 added, Firewall::DeleteRuleChange{"inet", "filter", "input", 3},
		 Firewall::SetRuleOrderChange{"inet",
										  "filter", "input",
										  {std::string("new-1"), std::uint64_t{4}}},
		 Firewall::AddRuleChange{tcpRule(23), ""}
	 });
	TestSupport::require(commands.size() == 4,
						 "other changes should fold into one rebuild");
	TestSupport::require(commands[0].contains("flush"),
						 "the rebuild should come first");
	TestSupport::require(
		commands[1]["add"]["rule"]["expr"][1]["match"]["right"] == 22,
		"the new rule should go where the order placed it");
	TestSupport::require(
		!commands[1]["add"]["rule"].contains("archangel_change_id"),
		"the change ID must not reach nftables");
	TestSupport::require(commands[2]["add"]["rule"]["expr"][0].contains("drop"),
						 "the existing rule should follow");
	TestSupport::require(
		commands[3]["add"]["rule"]["expr"][1]["match"]["right"] == 23,
		"a rule added after the order should go last");
}

void reorderingRequiresEveryRuleExactlyOnce() {
	const auto order =
		[](std::vector<std::variant<std::uint64_t, std::string>> entries) {
			return Firewall::SetRuleOrderChange{"inet", "filter", "input",
												std::move(entries)};
		};
	requireRejected(order({std::uint64_t{3}}), "a missing rule");
	requireRejected(order({std::uint64_t{3}, std::uint64_t{3}}),
					"a repeated rule");
	requireRejected(
		order({std::uint64_t{3}, std::uint64_t{4}, std::uint64_t{9}}),
		"an unknown rule");
	requireRejected(order({std::uint64_t{3}, std::string("nope")}),
					"an unknown change ID");
	requireRejected(Firewall::SetRuleOrderChange{"inet", "filter", "gone", {}},
					"a missing chain");
}

void buildsChainChanges() {
	const auto regular = transaction({
		Firewall::CreateChainChange{"inet", "filter", "fresh", {}}
	  });
	TestSupport::require(regular[0]["add"]["chain"]["name"] == "fresh" &&
							 !regular[0]["add"]["chain"].contains("hook"),
						 "a regular chain has no hook");

	const auto	base  = transaction({
		  Firewall::CreateChainChange{
									"inet", "filter", "fresh",
									Firewall::BaseChain{"filter", "forward", -10, "drop"}}
	});
	const json &chain = base[0]["add"]["chain"];
	TestSupport::require(chain["type"] == "filter" &&
							 chain["hook"] == "forward" &&
							 chain["prio"] == -10 && chain["policy"] == "drop",
						 "a base chain should carry its definition");

	const auto renamed = transaction({
		Firewall::RenameChainChange{"inet", "filter", "other", "better"}
	});
	TestSupport::require(renamed[0]["rename"]["chain"]["newname"] == "better",
						 "rename should name the new chain");

	const auto	policy	   = transaction({
		 Firewall::SetChainPolicyChange{"inet", "filter", "input", "drop"}
	  });
	const json &withPolicy = policy[0]["add"]["chain"];
	TestSupport::require(
		withPolicy["policy"] == "drop" && withPolicy["hook"] == "input" &&
			withPolicy["type"] == "filter" && withPolicy["prio"] == 0,
		"a policy needs the chain's full definition, or "
		"nftables silently ignores it");
	TestSupport::require(!withPolicy.contains("handle"),
						 "the definition must not name a handle");

	const auto deleted = transaction({
		Firewall::DeleteChainChange{"inet", "filter", "input"}
	  });
	TestSupport::require(deleted[0]["delete"]["chain"]["name"] == "input",
						 "delete should name the chain");
}

void rejectsInvalidChainChanges() {
	using Firewall::BaseChain;
	using Firewall::CreateChainChange;
	requireRejected(CreateChainChange{"inet", "filter", "input", {}},
					"an existing chain");
	requireRejected(CreateChainChange{"inet", "gone", "x", {}},
					"a missing table");
	requireRejected(CreateChainChange{"inet", "filter", "bad name", {}},
					"an invalid name");
	requireRejected(CreateChainChange{"bridge", "filter", "x", {}},
					"an unsupported family");
	requireRejected(
		CreateChainChange{
			"inet", "filter", "x", BaseChain{"nat", "input", 0, "accept"}
	 },
		"an unsupported type");
	requireRejected(
		CreateChainChange{
			"inet", "filter", "x", BaseChain{"filter", "ingress", 0, "accept"}
	  },
		"an unsupported hook");
	requireRejected(
		CreateChainChange{
			"inet", "filter", "x",
			BaseChain{"filter", "input", 5000, "accept"}
	},
		"an out-of-range priority");
	requireRejected(
		CreateChainChange{
			"inet", "filter", "x", BaseChain{"filter", "input", 0, "reject"}
	},
		"an unsupported policy");
	requireRejected(
		Firewall::RenameChainChange{"inet", "filter", "other", "input"},
		"a name in use");
	requireRejected(Firewall::RenameChainChange{"inet", "filter", "gone", "x"},
					"renaming a missing chain");
	requireRejected(
		Firewall::RenameChainChange{"inet", "filter", "other", "a b"},
		"an invalid new name");
	requireRejected(
		Firewall::SetChainPolicyChange{"inet", "filter", "other", "drop"},
		"a policy on a regular chain");
	requireRejected(
		Firewall::SetChainPolicyChange{"inet", "filter", "input", "x"},
		"an unsupported policy");
	requireRejected(Firewall::DeleteChainChange{"inet", "filter", "gone"},
					"deleting a missing chain");
}

void aRenamedChainsRulesCannotChangeInTheSameList() {
	// nftables applies a rename at the end of a transaction, so these would
	// fail.
	const Firewall::RenameChainChange rename{"inet", "filter", "input",
											 "renamed"};
	Firewall::RuleSpec				  onNewName = tcpRule(22);
	onNewName.chain								= "renamed";
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] {
			transaction({
				rename, Firewall::AddRuleChange{onNewName, ""}
			  });
		},
		"a rule on the new name");
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] {
			transaction({
				rename, Firewall::AddRuleChange{tcpRule(22), ""}
			});
		},
		"a rule on the old name");
	TestSupport::require(
		transaction({
						Firewall::AddRuleChange{tcpRule(22), ""},
						  rename
	})
				.size() == 2,
		"changing rules before the rename is fine");
}

void aReorderedChainCannotBeRenamedOrDeletedInTheSameList() {
	const Firewall::SetRuleOrderChange order{
		"inet", "filter", "input", {std::uint64_t{3}, std::uint64_t{4}}
	   };
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] {
			transaction({
				order,
				Firewall::RenameChainChange{"inet", "filter", "input", "x"}
			   });
		},
		"rename after reorder");
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] {
			transaction({
				order, Firewall::DeleteChainChange{"inet", "filter", "input"}
			 });
		},
		"delete after reorder");
	TestSupport::requireThrows<Firewall::ChangeRejectedError>(
		[&] {
			transaction({
				order, Firewall::DeleteTableChange{"inet", "filter"}
			});
		},
		"delete table after reorder");
}

void buildsTableChanges() {
	const auto created = transaction({
		Firewall::CreateTableChange{"ip", "fresh"},
		Firewall::CreateChainChange{"ip", "fresh", "c", {}}
	   });
	TestSupport::require(created[0]["add"]["table"]["name"] == "fresh" &&
							 created[1]["add"]["chain"]["table"] == "fresh",
						 "a new table can hold a new chain in the same list");

	TestSupport::require(
		transaction({
			Firewall::DeleteTableChange{
										"inet", "filter"}
	 })[0]["delete"]["table"]["name"] == "filter",
		"delete should name the table");

	const auto off = transaction({
		Firewall::SetTableEnabledChange{"inet", "filter", false}
	});
	TestSupport::require(off[0]["add"]["table"]["flags"] ==
							 json::array({"dormant"}),
						 "turning a table off sets dormant");
	const auto on = transaction({
		Firewall::SetTableEnabledChange{"inet", "filter", true}
	   });
	TestSupport::require(on[0]["add"]["table"]["flags"] == json::array(),
						 "turning a table on clears dormant");

	requireRejected(Firewall::CreateTableChange{"inet", "filter"},
					"an existing table");
	requireRejected(Firewall::CreateTableChange{"inet", "bad name"},
					"an invalid table name");
	requireRejected(Firewall::CreateTableChange{"netdev", "x"},
					"an unsupported family");
	requireRejected(Firewall::DeleteTableChange{"inet", "gone"},
					"deleting a missing table");
	requireRejected(Firewall::SetTableEnabledChange{"inet", "gone", false},
					"toggling a missing table");
}

void revisionsCoverWhatAChangeTouches() {
	const auto set = [](std::vector<Firewall::Change>		 changes,
						std::vector<Firewall::ChainRevision> expected = {}) {
		Firewall::ChangeSet result;
		result.expected = std::move(expected);
		result.changes	= std::move(changes);
		return result;
	};
	const Firewall::ChainRevision input{"inet", "filter", "input",
										revisionOf(LISTING, "input")};
	const Firewall::ChainRevision other{"inet", "filter", "other",
										revisionOf(LISTING, "other")};

	Firewall::Detail::requireCurrentRevisions(
		LISTING, set({
					 Firewall::CreateTableChange{"ip", "x"}
	   }));
	Firewall::Detail::requireCurrentRevisions(
		LISTING, set({
					 Firewall::CreateChainChange{"inet", "filter", "x", {}}
	   }));
	Firewall::RuleSpec onNew = tcpRule(1);
	onNew.chain				 = "x";
	Firewall::Detail::requireCurrentRevisions(
		LISTING, set({
					 Firewall::CreateChainChange{"inet", "filter", "x", {}},
					 Firewall::AddRuleChange{onNew, ""}
	   }));

	TestSupport::requireThrows<Firewall::InvalidRuleError>(
		[&] {
			Firewall::Detail::requireCurrentRevisions(
				LISTING,
				set({
					Firewall::DeleteChainChange{"inet", "filter", "input"}
			  }));
		},
		"deleting a chain needs its revision");
	TestSupport::requireThrows<Firewall::InvalidRuleError>(
		[&] {
			Firewall::Detail::requireCurrentRevisions(
				LISTING, set(
							 {
								 Firewall::DeleteTableChange{"inet", "filter"}
			  },
							 {input}));
		},
		"deleting a table needs the revision of every chain in it");
	Firewall::Detail::requireCurrentRevisions(
		LISTING, set(
					 {
						 Firewall::DeleteTableChange{"inet", "filter"}
	  },
					 {input, other}));
	TestSupport::requireThrows<Firewall::ChangeConflictError>(
		[&] {
			Firewall::Detail::requireCurrentRevisions(
				replaced(LISTING, R"({"drop":null})", R"({"accept":null})"),
				set(
					{
						Firewall::SetTableEnabledChange{"inet", "filter",
														false}
			  },
					{input, other}));
		},
		"a changed chain should stop a table being turned off");
}

void identifiesTheChangeItRejects() {
	Firewall::RuleSpec invalid = tcpRule(22);
	invalid.source_address	   = "192.168.1.5/24";
	const auto invalidRule	   = changeSet({
		Firewall::AddRuleChange{tcpRule(1), ""},
		Firewall::AddRuleChange{	invalid, ""}
	});
	const auto missingRule	   = changeSet({
		Firewall::AddRuleChange{tcpRule(1), ""},
		Firewall::DeleteRuleChange{"inet", "filter", "input", 3},
		Firewall::DeleteRuleChange{"inet", "filter", "input", 99}
	 });
	for (const auto &[set, index] : {
			 std::pair{invalidRule, std::size_t{1}},
			 std::pair{missingRule, std::size_t{2}}
	   }) {
		try {
			Firewall::Detail::buildTransaction(LISTING, set,
											   set.changes.size());
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
	reorderingRebuildsTheChainKeepingItsRules();
	reorderingPlacesNewRulesAndIncludesOtherChanges();
	reorderingRequiresEveryRuleExactlyOnce();
	buildsChainChanges();
	rejectsInvalidChainChanges();
	aRenamedChainsRulesCannotChangeInTheSameList();
	aReorderedChainCannotBeRenamedOrDeletedInTheSameList();
	buildsTableChanges();
	revisionsCoverWhatAChangeTouches();
	identifiesTheChangeItRejects();
	rejectsMalformedListings();
}
