#include "nft_import.hpp"

#include "firewall/config.hpp"
#include "json/json.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace {
using Json = nlohmann::json;

Json parseJson(const std::string &value, const char *description) {
	try {
		return Json::parse(value);
	} catch (const Json::exception &error) {
		throw std::runtime_error(std::string("Invalid ") + description +
								 " JSON: " + error.what());
	}
}

bool hasArchangelMarker(const Json &entry) {
	if (!entry.is_object() || !entry.contains("rule") ||
		!entry["rule"].is_object()) {
		return false;
	}
	const auto comment = entry["rule"].find("comment");
	return comment != entry["rule"].end() && comment->is_string() &&
		   comment->get<std::string>() == ARCHANGEL_RULE_COMMENT;
}
} // namespace

ArchangelRulesReplacement
buildArchangelRulesReplacement(const std::string &activeRuleset,
							   const std::string &managedRulesJson) {
	Json managedRules = parseJson(managedRulesJson, "Archangel rules");
	if (!managedRules.is_array()) {
		throw std::runtime_error("Archangel rules must be a JSON array");
	}
	for (Json &entry : managedRules) {
		if (!entry.is_object() || entry.size() != 1 ||
			!entry.contains("rule") || !hasArchangelMarker(entry)) {
			throw std::runtime_error("Archangel rules must contain only marked "
									 "nftables rule objects");
		}
		entry["rule"].erase("handle");
		entry["rule"].erase("index");
	}

	const Json active = parseJson(activeRuleset, "active nftables");
	if (!active.is_object() || !active.contains("nftables") ||
		!active["nftables"].is_array()) {
		throw std::runtime_error(
			"Active nftables ruleset has an invalid shape");
	}

	Json		commands = Json::array();
	std::size_t removed	 = 0;
	for (const Json &entry : active["nftables"]) {
		if (!hasArchangelMarker(entry)) {
			continue;
		}
		const Json &rule = entry["rule"];
		if (!rule.contains("family") || !rule["family"].is_string() ||
			!rule.contains("table") || !rule["table"].is_string() ||
			!rule.contains("chain") || !rule["chain"].is_string() ||
			!rule.contains("handle") ||
			!(rule["handle"].is_number_unsigned() ||
			  (rule["handle"].is_number_integer() && rule["handle"] > 0))) {
			throw std::runtime_error(
				"An active Archangel-managed rule has no valid delete handle");
		}
		Json target{
			{"family", rule["family"]},
			{ "table",  rule["table"]},
			{ "chain",  rule["chain"]},
			{"handle", rule["handle"]},
		};
		commands.push_back(Json{
			{"delete", Json{{"rule", std::move(target)}}}
		 });
		++removed;
	}
	for (const Json &entry : managedRules) {
		commands.push_back(Json{
			{"add", entry}
		  });
	}

	return {commands.empty() ? std::string()
							 : Json{{"nftables", std::move(commands)}}.dump(),
			removed, managedRules.size()};
}
