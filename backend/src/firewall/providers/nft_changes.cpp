#include "nft_changes.hpp"
#include "config/app_config.hpp"
#include "firewall/bundle.hpp"
#include "nft_rule.hpp"
#include "json/json.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

namespace Firewall::Detail {

namespace {
using Json	   = nlohmann::json;
using ChainKey = std::tuple<std::string, std::string, std::string>;

/**
 * @brief Parses a listing and returns its entries.
 * @param ruleset nftables JSON ruleset listing.
 * @return The listing's nftables array.
 * @throws std::runtime_error If the listing is malformed.
 */
Json listedEntries(const std::string &ruleset) {
	Json document;
	try {
		document = Json::parse(ruleset);
	} catch (const Json::exception &) {
		throw std::runtime_error("nftables returned invalid JSON");
	}
	if (!document.is_object() || !document.contains("nftables") ||
		!document["nftables"].is_array()) {
		throw std::runtime_error("nftables returned an invalid ruleset");
	}
	return std::move(document["nftables"]);
}

/**
 * @brief Removes counter values from a rule's statements.
 * @param rule Listed rule object, changed in place.
 * @return No value.
 */
void removeCounterValues(Json &rule) {
	const auto expression = rule.find("expr");
	if (expression == rule.end() || !expression->is_array()) {
		return;
	}
	for (Json &statement : *expression) {
		if (statement.is_object() && statement.contains("counter") &&
			statement["counter"].is_object()) {
			statement["counter"].erase("packets");
			statement["counter"].erase("bytes");
		}
	}
}

/**
 * @brief Hashes text with SHA-256.
 * @param text Text to hash.
 * @return Lowercase hexadecimal digest.
 * @throws std::runtime_error If hashing fails.
 */
std::string sha256(const std::string &text) {
	std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
	unsigned int							   length = 0;
	if (EVP_Digest(text.data(), text.size(), digest.data(), &length,
				   EVP_sha256(), nullptr) != 1) {
		throw std::runtime_error("Unable to hash firewall chain");
	}
	static constexpr char HEX[] = "0123456789abcdef";
	std::string			  result;
	for (unsigned int index = 0; index < length; ++index) {
		result += HEX[digest[index] >> 4];
		result += HEX[digest[index] & 0x0f];
	}
	return result;
}

/**
 * @brief Wraps an object in a transaction command.
 * @param verb Command verb, such as add or delete.
 * @param kind Object type, such as rule or chain.
 * @param object Object for the command.
 * @return One JSON command.
 */
Json command(const char *verb, const char *kind, Json object) {
	Json result;
	result[verb][kind] = std::move(object);
	return result;
}

/**
 * @brief Finds the existing chains a change list touches, in order.
 *
 * Chains the list itself creates are skipped, since they have no revision.
 *
 * @param entries Listing entries.
 * @param changes Change set to inspect.
 * @return Keys of the chains whose revisions must be current.
 */
std::set<ChainKey> touchedChains(const Json		 &entries,
								 const ChangeSet &changes) {
	std::set<ChainKey> touched;
	std::set<ChainKey> created;
	const auto touch = [&](const std::string &family, const std::string &table,
						   const std::string &chain) {
		const ChainKey key{family, table, chain};
		if (created.count(key) == 0) {
			touched.insert(key);
		}
	};
	const auto touchTable = [&](const std::string &family,
								const std::string &table) {
		for (const Json &entry : entries) {
			if (entry.is_object() && entry.contains("chain") &&
				entry["chain"].value("family", "") == family &&
				entry["chain"].value("table", "") == table) {
				touch(family, table, entry["chain"].value("name", ""));
			}
		}
	};
	for (const Change &change : changes.changes) {
		std::visit(
			[&](const auto &item) {
				using Type = std::decay_t<decltype(item)>;
				if constexpr (std::is_same_v<Type, AddRuleChange> ||
							  std::is_same_v<Type, ReplaceRuleChange>) {
					touch(item.rule.family, item.rule.table, item.rule.chain);
				} else if constexpr (std::is_same_v<Type, DeleteRuleChange> ||
									 std::is_same_v<Type, SetRuleOrderChange>) {
					touch(item.family, item.table, item.chain);
				} else if constexpr (std::is_same_v<Type, CreateChainChange>) {
					created.insert({item.family, item.table, item.name});
				} else if constexpr (std::is_same_v<Type, RenameChainChange>) {
					touch(item.family, item.table, item.name);
					created.insert({item.family, item.table, item.new_name});
				} else if constexpr (std::is_same_v<Type,
													SetChainPolicyChange> ||
									 std::is_same_v<Type, DeleteChainChange>) {
					touch(item.family, item.table, item.name);
				} else if constexpr (std::is_same_v<Type, DeleteTableChange> ||
									 std::is_same_v<Type,
													SetTableEnabledChange>) {
					touchTable(item.family, item.name);
				}
			},
			change);
	}
	return touched;
}

/**
 * @brief The ruleset as changes are applied to it in order.
 *
 * Tracks what a transaction would see, so that a problem is reported against
 * the change that causes it, and so that a reordered chain can be rebuilt with
 * every change to its rules included.
 */
class TransactionBuilder {
  public:
	/**
	 * @brief Loads the model from a listing.
	 * @param entries Listing entries.
	 * @param reordered Chains that are rebuilt at the end of the transaction.
	 */
	TransactionBuilder(const Json &entries, std::set<ChainKey> reordered)
		: reordered_(std::move(reordered)) {
		for (const Json &entry : entries) {
			if (!entry.is_object()) {
				continue;
			}
			if (entry.contains("table")) {
				const Json &table = entry["table"];
				tables_[{table.value("family", ""), table.value("name", "")}] =
					table;
			} else if (entry.contains("chain")) {
				const Json &chain				   = entry["chain"];
				chains_[{chain.value("family", ""), chain.value("table", ""),
						 chain.value("name", "")}] = chain;
			} else if (entry.contains("rule")) {
				const Json &rule = entry["rule"];
				rules_[{rule.value("family", ""), rule.value("table", ""),
						rule.value("chain", "")}]
					.push_back(rule);
			}
		}
	}

	/**
	 * @brief Adds one change to the transaction.
	 * @param change Change to apply.
	 * @param index Position of the change in its change set.
	 * @return No value.
	 * @throws ChangeRejectedError If the change can't be applied at this point.
	 */
	void apply(const Change &change, std::size_t index) {
		index_ = index;
		std::visit([&](const auto &item) { applyChange(item); }, change);
	}

	/**
	 * @brief Finishes the transaction, rebuilding any reordered chains.
	 * @return Serialized JSON document accepted by libnftables.
	 */
	std::string finish() {
		for (const ChainKey &key : reordered_) {
			Json chain;
			chain["family"] = std::get<0>(key);
			chain["table"]	= std::get<1>(key);
			chain["name"]	= std::get<2>(key);
			commands_.push_back(command("flush", "chain", std::move(chain)));
			for (Json rule : rules_[key]) {
				rule.erase("handle");
				rule.erase("index");
				rule.erase(PLACEHOLDER);
				commands_.push_back(command("add", "rule", std::move(rule)));
			}
		}
		return Json{
			{"nftables", std::move(commands_)}
		  }
			.dump();
	}

  private:
	// Marks a rule added in this list, until a rebuild gives it a real handle.
	static constexpr const char *PLACEHOLDER = "archangel_change_id";

	[[noreturn]] void reject(const std::string &message) const {
		throw ChangeRejectedError(index_, message);
	}

	void requireFamily(const std::string &family) const {
		if (family != "ip" && family != "ip6" && family != "inet") {
			reject("family must be ip, ip6, or inet");
		}
	}

	void requireName(const std::string &name) const {
		if (!isIdentifier(name)) {
			reject("Names must use letters, digits, _, or -, and can't start "
				   "with a digit or -");
		}
	}

	/** @brief Requires a chain whose rules this list can still change. */
	std::vector<Json> &rulesOf(const ChainKey &key) {
		if (chains_.count(key) == 0) {
			reject("This chain doesn't exist");
		}
		if (renamed_.count(key) != 0) {
			reject("A chain's rules can't be changed in the same list as "
				   "renaming it");
		}
		return rules_[key];
	}

	/** @brief Finds an existing rule by handle. */
	std::vector<Json>::iterator findRule(std::vector<Json> &rules,
										 std::uint64_t		handle) {
		const auto found =
			std::find_if(rules.begin(), rules.end(), [&](const Json &rule) {
				return rule.value("handle", std::uint64_t{0}) == handle;
			});
		if (found == rules.end()) {
			reject("This rule no longer exists");
		}
		return found;
	}

	void validate(const RuleSpec &rule) const {
		try {
			validateRule(rule);
		} catch (const InvalidRuleError &error) {
			reject(error.what());
		}
	}

	void applyChange(const AddRuleChange &change) {
		validate(change.rule);
		const ChainKey	   key{change.rule.family, change.rule.table,
						   change.rule.chain};
		std::vector<Json> &rules = rulesOf(key);
		Json			   rule;
		rule["family"]	= change.rule.family;
		rule["table"]	= change.rule.table;
		rule["chain"]	= change.rule.chain;
		rule["comment"] = ARCHANGEL_RULE_COMMENT;
		rule["expr"]	= ruleExpressions(change.rule);
		if (reordered_.count(key) == 0) {
			commands_.push_back(command("add", "rule", rule));
		}
		if (!change.id.empty()) {
			rule[PLACEHOLDER] = change.id;
		}
		rules.push_back(std::move(rule));
	}

	void applyChange(const DeleteRuleChange &change) {
		const ChainKey	   key{change.family, change.table, change.chain};
		std::vector<Json> &rules = rulesOf(key);
		const auto		   found = findRule(rules, change.handle);
		rules.erase(found);
		if (reordered_.count(key) == 0) {
			Json rule;
			rule["family"] = change.family;
			rule["table"]  = change.table;
			rule["chain"]  = change.chain;
			rule["handle"] = change.handle;
			commands_.push_back(command("delete", "rule", std::move(rule)));
		}
	}

	void applyChange(const ReplaceRuleChange &change) {
		validate(change.rule);
		const ChainKey	   key{change.rule.family, change.rule.table,
						   change.rule.chain};
		std::vector<Json> &rules = rulesOf(key);
		Json			  &rule	 = *findRule(rules, change.handle);
		// Keeps a managed rule managed, and an unmanaged one unmanaged.
		rule["expr"] = ruleExpressions(change.rule);
		if (reordered_.count(key) == 0) {
			commands_.push_back(command("replace", "rule", rule));
		}
	}

	void applyChange(const SetRuleOrderChange &change) {
		const ChainKey	   key{change.family, change.table, change.chain};
		std::vector<Json> &rules = rulesOf(key);
		std::vector<Json>  ordered;
		std::vector<bool>  used(rules.size(), false);
		for (const auto &entry : change.order) {
			bool placed = false;
			for (std::size_t index = 0; index < rules.size() && !placed;
				 ++index) {
				const Json &rule	 = rules[index];
				const bool	matching = std::visit(
					 [&](const auto &value) {
						 using Type = std::decay_t<decltype(value)>;
						 if constexpr (std::is_same_v<Type, std::uint64_t>) {
							 return rule.contains("handle") &&
									rule.value("handle", std::uint64_t{0}) ==
										value;
						 } else {
							 return rule.value(PLACEHOLDER, "") == value;
						 }
					 },
					 entry);
				if (matching && !used[index]) {
					used[index] = true;
					ordered.push_back(rule);
					placed = true;
				}
			}
			if (!placed) {
				reject("The new order lists a rule the chain doesn't have");
			}
		}
		if (ordered.size() != rules.size()) {
			reject("The new order must list every rule in the chain");
		}
		rules = std::move(ordered);
	}

	void applyChange(const CreateChainChange &change) {
		requireFamily(change.family);
		requireName(change.name);
		if (tables_.count({change.family, change.table}) == 0) {
			reject("This table doesn't exist");
		}
		const ChainKey key{change.family, change.table, change.name};
		if (chains_.count(key) != 0) {
			reject("A chain with this name already exists");
		}
		Json chain;
		chain["family"] = change.family;
		chain["table"]	= change.table;
		chain["name"]	= change.name;
		if (change.base) {
			const BaseChain &base = *change.base;
			// NAT chains arrive with NAT rules; every other type is out of
			// scope.
			if (base.type != "filter") {
				reject("A chain's type must be filter");
			}
			static const std::set<std::string> hooks{
				"prerouting", "input", "forward", "output", "postrouting"};
			if (hooks.count(base.hook) == 0) {
				reject("A chain's hook must be prerouting, input, forward, "
					   "output, or postrouting");
			}
			if (base.priority < -Config::Limits::MAX_CHAIN_PRIORITY ||
				base.priority > Config::Limits::MAX_CHAIN_PRIORITY) {
				reject("A chain's priority must be between -" +
					   std::to_string(Config::Limits::MAX_CHAIN_PRIORITY) +
					   " and " +
					   std::to_string(Config::Limits::MAX_CHAIN_PRIORITY));
			}
			requirePolicy(base.policy);
			chain["type"]	= base.type;
			chain["hook"]	= base.hook;
			chain["prio"]	= base.priority;
			chain["policy"] = base.policy;
		}
		commands_.push_back(command("add", "chain", chain));
		chains_[key] = std::move(chain);
	}

	void requirePolicy(const std::string &policy) const {
		if (policy != "accept" && policy != "drop") {
			reject("A chain's policy must be accept or drop");
		}
	}

	void requireChain(const ChainKey &key) const {
		if (chains_.count(key) == 0) {
			reject("This chain doesn't exist");
		}
		if (reordered_.count(key) != 0) {
			reject("A chain can't be renamed or deleted in the same list as "
				   "reordering it");
		}
	}

	void applyChange(const RenameChainChange &change) {
		requireFamily(change.family);
		requireName(change.new_name);
		const ChainKey key{change.family, change.table, change.name};
		const ChainKey target{change.family, change.table, change.new_name};
		requireChain(key);
		if (renamed_.count(key) != 0) {
			reject("A chain can only be renamed once in a list");
		}
		if (chains_.count(target) != 0) {
			reject("A chain with this name already exists");
		}
		Json chain;
		chain["family"]	 = change.family;
		chain["table"]	 = change.table;
		chain["name"]	 = change.name;
		chain["newname"] = change.new_name;
		commands_.push_back(command("rename", "chain", std::move(chain)));
		Json renamed	= chains_.at(key);
		renamed["name"] = change.new_name;
		chains_[target] = std::move(renamed);
		renamed_.insert(key);
		renamed_.insert(target);
	}

	void applyChange(const SetChainPolicyChange &change) {
		requirePolicy(change.policy);
		const ChainKey key{change.family, change.table, change.name};
		const auto	   found = chains_.find(key);
		if (found == chains_.end() || !found->second.contains("hook")) {
			reject("Only a base chain has a policy");
		}
		found->second["policy"] = change.policy;
		// nftables silently ignores a policy without the chain's full
		// definition.
		Json chain = found->second;
		chain.erase("handle");
		commands_.push_back(command("add", "chain", std::move(chain)));
	}

	void applyChange(const DeleteChainChange &change) {
		const ChainKey key{change.family, change.table, change.name};
		requireChain(key);
		Json chain;
		chain["family"] = change.family;
		chain["table"]	= change.table;
		chain["name"]	= change.name;
		commands_.push_back(command("delete", "chain", std::move(chain)));
		chains_.erase(key);
		rules_.erase(key);
	}

	void applyChange(const CreateTableChange &change) {
		requireFamily(change.family);
		requireName(change.name);
		if (tables_.count({change.family, change.name}) != 0) {
			reject("A table with this name already exists");
		}
		Json table;
		table["family"] = change.family;
		table["name"]	= change.name;
		commands_.push_back(command("add", "table", table));
		tables_[{change.family, change.name}] = std::move(table);
	}

	void applyChange(const DeleteTableChange &change) {
		requireFamily(change.family);
		if (tables_.erase({change.family, change.name}) == 0) {
			reject("This table doesn't exist");
		}
		for (const auto &[key, chain] : chains_) {
			if (std::get<0>(key) == change.family &&
				std::get<1>(key) == change.name && reordered_.count(key) != 0) {
				reject("A table can't be deleted in the same list as "
					   "reordering one of its chains");
			}
		}
		std::erase_if(chains_, [&](const auto &item) {
			return std::get<0>(item.first) == change.family &&
				   std::get<1>(item.first) == change.name;
		});
		std::erase_if(rules_, [&](const auto &item) {
			return std::get<0>(item.first) == change.family &&
				   std::get<1>(item.first) == change.name;
		});
		Json table;
		table["family"] = change.family;
		table["name"]	= change.name;
		commands_.push_back(command("delete", "table", std::move(table)));
	}

	void applyChange(const SetTableEnabledChange &change) {
		requireFamily(change.family);
		const auto found = tables_.find({change.family, change.name});
		if (found == tables_.end()) {
			reject("This table doesn't exist");
		}
		Json flags = Json::array();
		if (found->second.contains("flags")) {
			const Json &existing = found->second["flags"];
			for (const Json &flag :
				 existing.is_array() ? existing : Json::array({existing})) {
				if (flag != "dormant") {
					flags.push_back(flag);
				}
			}
		}
		if (!change.enabled) {
			flags.push_back("dormant");
		}
		found->second["flags"] = flags;
		Json table;
		table["family"] = change.family;
		table["name"]	= change.name;
		table["flags"]	= std::move(flags);
		commands_.push_back(command("add", "table", std::move(table)));
	}

	std::map<std::pair<std::string, std::string>, Json> tables_;
	std::map<ChainKey, Json>							chains_;
	std::map<ChainKey, std::vector<Json>>				rules_;
	std::set<ChainKey>									reordered_;
	std::set<ChainKey>									renamed_;
	Json		commands_ = Json::array();
	std::size_t index_	  = 0;
};
} // namespace

std::vector<ChainRevision> chainRevisions(const std::string &ruleset) {
	const Json entries = listedEntries(ruleset);
	// Hash each chain's definition followed by its rules, in listing order.
	std::map<ChainKey, std::string> content;
	for (const Json &entry : entries) {
		if (!entry.is_object()) {
			continue;
		}
		if (entry.contains("chain")) {
			const Json &chain = entry["chain"];
			content[{chain.value("family", ""), chain.value("table", ""),
					 chain.value("name", "")}] += chain.dump();
		} else if (entry.contains("rule")) {
			Json rule = entry["rule"];
			removeCounterValues(rule);
			content[{rule.value("family", ""), rule.value("table", ""),
					 rule.value("chain", "")}] += rule.dump();
		}
	}
	std::vector<ChainRevision> revisions;
	for (const auto &[key, text] : content) {
		revisions.push_back({std::get<0>(key), std::get<1>(key),
							 std::get<2>(key), sha256(text)});
	}
	return revisions;
}

void requireCurrentRevisions(const std::string &ruleset,
							 const ChangeSet   &changes) {
	std::map<ChainKey, std::string> current;
	for (ChainRevision &revision : chainRevisions(ruleset)) {
		current[{revision.family, revision.table, revision.chain}] =
			std::move(revision.revision);
	}
	std::map<ChainKey, std::string> expected;
	for (const ChainRevision &revision : changes.expected) {
		expected[{revision.family, revision.table, revision.chain}] =
			revision.revision;
	}
	for (const ChainKey &key : touchedChains(listedEntries(ruleset), changes)) {
		const auto reviewed = expected.find(key);
		if (reviewed == expected.end()) {
			throw InvalidRuleError(
				"expected_revisions must include every chain a change touches");
		}
		const auto found = current.find(key);
		if (found == current.end() || found->second != reviewed->second) {
			throw ChangeConflictError(
				"A chain has changed since these changes were reviewed");
		}
	}
}

std::string buildTransaction(const std::string &ruleset,
							 const ChangeSet &changes, std::size_t count) {
	std::set<ChainKey> reordered;
	for (std::size_t index = 0; index < count; ++index) {
		if (const auto *order =
				std::get_if<SetRuleOrderChange>(&changes.changes.at(index))) {
			reordered.insert({order->family, order->table, order->chain});
		}
	}
	TransactionBuilder builder(listedEntries(ruleset), std::move(reordered));
	for (std::size_t index = 0; index < count; ++index) {
		builder.apply(changes.changes.at(index), index);
	}
	return builder.finish();
}

} // namespace Firewall::Detail
