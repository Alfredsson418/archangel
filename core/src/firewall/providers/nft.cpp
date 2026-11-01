#include "firewall/providers/nft.hpp"
#include "config/app_config.hpp"
#include "firewall/bundle.hpp"
#include "logs/logger.hpp"
#include "nft_import.hpp"
#include "nft_statistics.hpp"
#include "json/json.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <set>
#include <utility>

namespace {

/**
 * @brief Checks that a value is safe to use as an nftables table or chain name.
 * @param value Candidate identifier.
 * @return True if it uses the accepted ASCII identifier syntax.
 */
bool isIdentifier(const std::string &value) {
	const auto isAlpha = [](unsigned char character) {
		return (character >= 'a' && character <= 'z') ||
			   (character >= 'A' && character <= 'Z');
	};
	const auto isDigit = [](unsigned char character) {
		return character >= '0' && character <= '9';
	};

	if (value.empty() ||
		value.size() > AppConfigLimits::MAX_FIREWALL_IDENTIFIER_LENGTH ||
		!(isAlpha(static_cast<unsigned char>(value.front())) ||
		  value.front() == '_')) {
		return false;
	}

	for (const unsigned char character : value) {
		if (!(isAlpha(character) || isDigit(character) || character == '_' ||
			  character == '-')) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Tests whether a string is a valid IPv4 address.
 * @param address Address text to parse.
 * @return True if inet_pton accepts it as IPv4.
 */
bool isIpv4Address(const std::string &address) {
	in_addr parsed{};
	return inet_pton(AF_INET, address.c_str(), &parsed) == 1;
}

/**
 * @brief Tests whether a string is a valid IPv6 address.
 * @param address Address text to parse.
 * @return True if inet_pton accepts it as IPv6.
 */
bool isIpv6Address(const std::string &address) {
	in6_addr parsed{};
	return inet_pton(AF_INET6, address.c_str(), &parsed) == 1;
}

/**
 * @brief Validates an address and its compatibility with the nftables family.
 * @param family Requested nftables family.
 * @param address Address text supplied by the caller.
 * @return No value.
 * @throws InvalidRuleError If the address is invalid or incompatible.
 */
void validateAddress(const std::string &family, const std::string &address) {
	const bool ipv4 = isIpv4Address(address);
	const bool ipv6 = isIpv6Address(address);
	if ((!ipv4 && !ipv6) || (family == "ip" && !ipv4) ||
		(family == "ip6" && !ipv6)) {
		throw InvalidRuleError("An address is invalid for the selected family");
	}
}

/**
 * @brief Validates every supported field and required match in a rule.
 * @param rule Backend-neutral rule description.
 * @return No value.
 * @throws InvalidRuleError If a field is unsupported or invalid.
 */
void validateRule(const RuleSpec &rule) {
	if (rule.family != "ip" && rule.family != "ip6" && rule.family != "inet") {
		throw InvalidRuleError("family must be ip, ip6, or inet");
	}
	if (!isIdentifier(rule.table) || !isIdentifier(rule.chain)) {
		throw InvalidRuleError(
			"table and chain must be valid nftables identifiers");
	}
	if (rule.protocol != "tcp" && rule.protocol != "udp") {
		throw InvalidRuleError("protocol must be tcp or udp");
	}
	if (rule.action != "accept" && rule.action != "drop" &&
		rule.action != "reject") {
		throw InvalidRuleError("action must be accept, drop, or reject");
	}
	if (!rule.source_address && !rule.destination_address &&
		!rule.destination_port) {
		throw InvalidRuleError(
			"at least one address or destination port match is required");
	}
	if (rule.source_address) {
		validateAddress(rule.family, *rule.source_address);
	}
	if (rule.destination_address) {
		validateAddress(rule.family, *rule.destination_address);
	}
}

/**
 * @brief Builds an nftables JSON equality match statement.
 * @param left Expression to compare, such as a payload or meta selector.
 * @param right Value the expression must equal.
 * @return A JSON match statement.
 */
nlohmann::json equalityMatch(nlohmann::json left, nlohmann::json right) {
	nlohmann::json match;
	match["op"]	   = "==";
	match["left"]  = std::move(left);
	match["right"] = std::move(right);
	return nlohmann::json{
		{"match", std::move(match)}
	   };
}

/**
 * @brief Builds a payload selector expression, such as ip saddr.
 * @param protocol Payload protocol, such as ip, ip6, or tcp.
 * @param field Payload field, such as saddr or dport.
 * @return A JSON payload expression.
 */
nlohmann::json payload(const std::string &protocol, const char *field) {
	nlohmann::json selector;
	selector["protocol"] = protocol;
	selector["field"]	 = field;
	return nlohmann::json{
		{"payload", std::move(selector)}
	};
}

/**
 * @brief Builds an address match using the correct nftables IP protocol.
 * @param address Validated IPv4 or IPv6 address.
 * @param direction nftables direction field, such as saddr or daddr.
 * @return A JSON match statement for the address.
 */
nlohmann::json addressMatch(const std::string &address, const char *direction) {
	return equalityMatch(
		payload(isIpv4Address(address) ? "ip" : "ip6", direction), address);
}

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
	Logger::Firewall::log(
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
	Logger::Firewall::log("Replaced Archangel-managed firewall rules removed=" +
						  std::to_string(replacement.removed) +
						  " added=" + std::to_string(replacement.added));
}

FirewallStatistics Nftables::getStatistics() {
	return statisticsFromNftRuleset(listRules());
}

void Nftables::addRule(const RuleSpec &rule) {
	validateRule(rule);

	// Build JSON commands rather than command text so request values can only
	// ever be data, never nftables syntax.
	nlohmann::json expressions = nlohmann::json::array();
	if (rule.source_address) {
		expressions.push_back(addressMatch(*rule.source_address, "saddr"));
	}
	if (rule.destination_address) {
		expressions.push_back(addressMatch(*rule.destination_address, "daddr"));
	}
	expressions.push_back(equalityMatch(
		nlohmann::json{
			{"meta", nlohmann::json{{"key", "l4proto"}}}
	},
		rule.protocol));
	if (rule.destination_port) {
		expressions.push_back(equalityMatch(payload(rule.protocol, "dport"),
											*rule.destination_port));
	}
	expressions.push_back(nlohmann::json{
		{rule.action, nullptr}
	  });

	nlohmann::json command;
	command["family"]  = rule.family;
	command["table"]   = rule.table;
	command["chain"]   = rule.chain;
	command["comment"] = ARCHANGEL_RULE_COMMENT;
	command["expr"]	   = std::move(expressions);

	std::lock_guard<std::mutex> lock(mutex_);
	executeJson(ruleCommand("add", std::move(command)));
	Logger::Firewall::log("Added a " + rule.protocol + " rule to " +
						  rule.family + " " + rule.table + " " + rule.chain);
}

void Nftables::deleteRule(const std::string &family, const std::string &table,
						  const std::string &chain, std::uint64_t handle) {
	if ((family != "ip" && family != "ip6" && family != "inet") ||
		!isIdentifier(table) || !isIdentifier(chain) || handle == 0) {
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
	Logger::Firewall::log("Deleted rule handle " + std::to_string(handle) +
						  " from " + family + " " + table + " " + chain);
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
