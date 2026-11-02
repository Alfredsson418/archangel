#include "firewall/providers/nft.hpp"
#include "config/app_config.hpp"
#include "firewall/bundle.hpp"
#include "logs/logger.hpp"
#include "nft_import.hpp"
#include "nft_rule.hpp"
#include "nft_statistics.hpp"
#include "json/json.hpp"
#include <cstdint>
#include <set>
#include <utility>

namespace Firewall {

namespace {

/**
 * @brief Wraps one nftables JSON command in a command document.
 * @param verb Command verb, such as add or delete.
 * @param rule Rule object for the command.
 * @return Serialized JSON document accepted by libnftables.
 */
std::string ruleCommand(const char *verb, nlohmann::json rule) {
	nlohmann::json command;
	command[verb]["rule"] = std::move(rule);
	nlohmann::json document;
	document["nftables"] = nlohmann::json::array({std::move(command)});
	return document.dump();
}

} // namespace

Nftables::Nftables() : context_(nullptr) {
	context_ = nft_ctx_new(0);

	if (context_ == nullptr) {
		throw std::runtime_error("Failed to create nftables context");
	}

	// Ask libnftables to return JSON instead of human-readable output.
	nft_ctx_output_set_flags(context_, nft_ctx_output_get_flags(context_) |
										   NFT_CTX_OUTPUT_JSON);

	// Store output internally so we can retrieve it afterwards.
	if (nft_ctx_buffer_output(context_) != 0) {
		nft_ctx_free(context_);
		context_ = nullptr;

		throw std::runtime_error("Failed to enable nftables output buffering");
	}
}

Nftables::~Nftables() {
	if (context_ != nullptr) {
		nft_ctx_free(context_);
	}
}

std::string Nftables::listRules() {
	std::lock_guard<std::mutex> lock(mutex_);
	execute("list ruleset");

	const char *output = nft_ctx_get_output_buffer(context_);
	if (output == nullptr) {
		throw std::runtime_error("nftables returned no ruleset output");
	}
	return output;
}

std::string Nftables::exportRuleset() {
	const std::string ruleset = listRules();
	try {
		const auto parsed = nlohmann::json::parse(ruleset);
		if (!parsed.is_object() || !parsed.contains("nftables") ||
			!parsed["nftables"].is_array()) {
			throw std::runtime_error(
				"nftables returned an invalid JSON ruleset");
		}
		return parsed.dump(2);
	} catch (const nlohmann::json::exception &error) {
		throw std::runtime_error(
			std::string("Unable to encode nftables JSON: ") + error.what());
	}
}

void Nftables::importRuleset(const std::string &ruleset, bool replaceAll) {
	using Json = nlohmann::json;
	Json document;
	try {
		document = Json::parse(ruleset);
	} catch (const Json::exception &error) {
		throw std::runtime_error(
			std::string("Invalid nftables JSON ruleset: ") + error.what());
	}
	if (!document.is_object() || !document.contains("nftables") ||
		!document["nftables"].is_array()) {
		throw std::runtime_error(
			"nftables JSON ruleset must contain an nftables array");
	}

	static const std::set<std::string> supportedObjects{
		"table",   "chain",		 "rule",		  "set",   "map",
		"element", "flowtable",	 "counter",		  "quota", "ct_helper",
		"limit",   "ct_timeout", "ct_expectation"};
	Json commands = Json::array();
	if (replaceAll) {
		commands.push_back(Json{
			{"flush", Json{{"ruleset", nullptr}}}
		 });
	}
	for (const Json &entry : document["nftables"]) {
		if (!entry.is_object() || entry.size() != 1) {
			throw std::runtime_error(
				"Each nftables ruleset entry must be a single object");
		}
		const auto object = entry.begin();
		if (object.key() == "metainfo") {
			continue;
		}
		if (supportedObjects.find(object.key()) == supportedObjects.end() ||
			!object.value().is_object()) {
			throw std::runtime_error("Unsupported nftables ruleset object");
		}
		Json value = object.value();
		value.erase("handle");
		value.erase("index");
		commands.push_back(Json{
			{"add", Json{{object.key(), std::move(value)}}}
		   });
	}
	const std::string input = Json{
		{"nftables",
		 std::move(commands)}
	 }.dump();

	std::lock_guard<std::mutex> lock(mutex_);
	executeJson(input);
	Logs::Logger::Firewall::log(
		replaceAll ? "Replaced the complete nftables ruleset from JSON config"
				   : "Merged nftables JSON config into the active ruleset");
}

void Nftables::replaceArchangelRuleset(const std::string &rules) {
	// Hold the lock across the ruleset snapshot and transaction so another
	// operation on this backend cannot invalidate the handles in between.
	std::lock_guard<std::mutex> lock(mutex_);
	execute("list ruleset");
	const char *output = nft_ctx_get_output_buffer(context_);
	if (output == nullptr) {
		throw std::runtime_error("nftables returned no ruleset output");
	}

	const ArchangelRulesReplacement replacement =
		buildArchangelRulesReplacement(output, rules);
	if (!replacement.transaction.empty()) {
		executeJson(replacement.transaction);
	}
	Logs::Logger::Firewall::log(
		"Replaced Archangel-managed firewall rules removed=" +
		std::to_string(replacement.removed) +
		" added=" + std::to_string(replacement.added));
}

Statistics Nftables::getStatistics() {
	return statisticsFromNftRuleset(listRules());
}

void Nftables::addRule(const RuleSpec &rule) {
	Detail::validateRule(rule);

	nlohmann::json command;
	command["family"]  = rule.family;
	command["table"]   = rule.table;
	command["chain"]   = rule.chain;
	command["comment"] = ARCHANGEL_RULE_COMMENT;
	command["expr"]	   = Detail::ruleExpressions(rule);

	std::lock_guard<std::mutex> lock(mutex_);
	executeJson(ruleCommand("add", std::move(command)));
	Logs::Logger::Firewall::log("Added a rule to " + rule.family + " " +
								rule.table + " " + rule.chain);
}

void Nftables::deleteRule(const std::string &family, const std::string &table,
						  const std::string &chain, std::uint64_t handle) {
	if ((family != "ip" && family != "ip6" && family != "inet") ||
		!Detail::isIdentifier(table) || !Detail::isIdentifier(chain) ||
		handle == 0) {
		throw InvalidRuleError(
			"family, table, chain, or rule handle is invalid");
	}

	nlohmann::json command;
	command["family"] = family;
	command["table"]  = table;
	command["chain"]  = chain;
	command["handle"] = handle;
	std::lock_guard<std::mutex> lock(mutex_);
	executeJson(ruleCommand("delete", std::move(command)));
	Logs::Logger::Firewall::log("Deleted rule handle " +
								std::to_string(handle) + " from " + family +
								" " + table + " " + chain);
}

void Nftables::executeJson(const std::string &commands) {
	const unsigned int inputFlags = nft_ctx_input_get_flags(context_);
	nft_ctx_input_set_flags(context_, inputFlags | NFT_CTX_INPUT_JSON);
	try {
		execute(commands);
		nft_ctx_input_set_flags(context_, inputFlags);
	} catch (...) {
		nft_ctx_input_set_flags(context_, inputFlags);
		throw;
	}
}

void Nftables::execute(const std::string &command) {
	// Clear any output left from a previous command.
	nft_ctx_unbuffer_output(context_);

	if (nft_ctx_buffer_output(context_) != 0) {
		throw std::runtime_error("Failed to enable nftables output buffering");
	}

	const int result = nft_run_cmd_from_buffer(context_, command.c_str());

	if (result != 0) {
		const char *error = nft_ctx_get_error_buffer(context_);

		if (error != nullptr) {
			throw std::runtime_error(error);
		}

		throw std::runtime_error("Failed to execute nftables command");
	}
}

} // namespace Firewall
