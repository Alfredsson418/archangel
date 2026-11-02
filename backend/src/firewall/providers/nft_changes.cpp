#include "nft_changes.hpp"
#include "firewall/bundle.hpp"
#include "nft_rule.hpp"
#include "json/json.hpp"

#include <openssl/evp.h>

#include <array>
#include <map>
#include <stdexcept>
#include <tuple>
#include <utility>

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
 * @brief Names the chain a change touches.
 * @param change Change to inspect.
 * @return The chain's family, table, and name.
 */
ChainKey touchedChain(const Change &change) {
	if (const auto *add = std::get_if<AddRuleChange>(&change)) {
		return {add->rule.family, add->rule.table, add->rule.chain};
	}
	if (const auto *replace = std::get_if<ReplaceRuleChange>(&change)) {
		return {replace->rule.family, replace->rule.table, replace->rule.chain};
	}
	const auto &remove = std::get<DeleteRuleChange>(change);
	return {remove.family, remove.table, remove.chain};
}

/**
 * @brief Wraps a rule object in a transaction command.
 * @param verb Command verb, such as add or delete.
 * @param rule Rule object for the command.
 * @return One JSON command.
 */
Json ruleCommand(const char *verb, Json rule) {
	Json command;
	command[verb]["rule"] = std::move(rule);
	return command;
}

/**
 * @brief Finds the rules present in each chain.
 * @param entries Listing entries.
 * @return Rule objects by handle, keyed by chain.
 */
std::map<ChainKey, std::map<std::uint64_t, Json>>
listedRules(const Json &entries) {
	std::map<ChainKey, std::map<std::uint64_t, Json>> rules;
	for (const Json &entry : entries) {
		if (!entry.is_object() || !entry.contains("rule")) {
			continue;
		}
		const Json &rule = entry["rule"];
		rules[{rule.value("family", ""), rule.value("table", ""),
			   rule.value("chain", "")}]
			 [rule.value("handle", std::uint64_t{0})] = rule;
	}
	return rules;
}

/**
 * @brief Validates a rule, reporting a problem against its change.
 * @param rule Rule to validate.
 * @param index Position of the change in its change set.
 * @return No value.
 * @throws ChangeRejectedError If the rule is invalid.
 */
void validateChangeRule(const RuleSpec &rule, std::size_t index) {
	try {
		validateRule(rule);
	} catch (const InvalidRuleError &error) {
		throw ChangeRejectedError(index, error.what());
	}
}
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
	for (const Change &change : changes.changes) {
		const ChainKey key		= touchedChain(change);
		const auto	   reviewed = expected.find(key);
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
	const auto rules	= listedRules(listedEntries(ruleset));
	Json	   commands = Json::array();
	for (std::size_t index = 0; index < count; ++index) {
		const Change &change = changes.changes.at(index);
		if (const auto *add = std::get_if<AddRuleChange>(&change)) {
			validateChangeRule(add->rule, index);
			Json rule;
			rule["family"]	= add->rule.family;
			rule["table"]	= add->rule.table;
			rule["chain"]	= add->rule.chain;
			rule["comment"] = ARCHANGEL_RULE_COMMENT;
			rule["expr"]	= ruleExpressions(add->rule);
			commands.push_back(ruleCommand("add", std::move(rule)));
			continue;
		}
		if (const auto *replace = std::get_if<ReplaceRuleChange>(&change)) {
			validateChangeRule(replace->rule, index);
			const auto chain =
				rules.find({replace->rule.family, replace->rule.table,
							replace->rule.chain});
			if (chain == rules.end() ||
				chain->second.count(replace->handle) == 0) {
				throw ChangeRejectedError(index, "This rule no longer exists");
			}
			Json rule;
			rule["family"] = replace->rule.family;
			rule["table"]  = replace->rule.table;
			rule["chain"]  = replace->rule.chain;
			rule["handle"] = replace->handle;
			rule["expr"]   = ruleExpressions(replace->rule);
			// Keeps a managed rule managed, and an unmanaged one unmanaged.
			const Json &existing = chain->second.at(replace->handle);
			if (existing.contains("comment")) {
				rule["comment"] = existing["comment"];
			}
			commands.push_back(ruleCommand("replace", std::move(rule)));
			continue;
		}
		const auto &remove = std::get<DeleteRuleChange>(change);
		const auto	chain =
			rules.find({remove.family, remove.table, remove.chain});
		if (chain == rules.end() || chain->second.count(remove.handle) == 0) {
			throw ChangeRejectedError(index, "This rule no longer exists");
		}
		Json rule;
		rule["family"] = remove.family;
		rule["table"]  = remove.table;
		rule["chain"]  = remove.chain;
		rule["handle"] = remove.handle;
		commands.push_back(ruleCommand("delete", std::move(rule)));
	}
	return Json{
		{"nftables", std::move(commands)}
	 }
		.dump();
}

} // namespace Firewall::Detail
