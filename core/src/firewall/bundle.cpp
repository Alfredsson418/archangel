#include "firewall/bundle.hpp"
#include "json/json.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace {
using Json = nlohmann::json;

Json parseRuleset(const Json &value, const char *description) {
	if (!value.is_object() || value.size() != 1 ||
		!value.contains("nftables") || !value["nftables"].is_array()) {
		throw std::runtime_error(std::string(description) +
								 " must contain an nftables array");
	}
	return value;
}

bool isArchangelRule(const Json &entry) {
	if (!entry.is_object() || entry.size() != 1 || !entry.contains("rule") ||
		!entry["rule"].is_object()) {
		return false;
	}
	const auto comment = entry["rule"].find("comment");
	return comment != entry["rule"].end() && comment->is_string() &&
		   comment->get<std::string>() == ARCHANGEL_RULE_COMMENT;
}

Json parseJson(const std::string &content) {
	try {
		return Json::parse(content);
	} catch (const Json::exception &error) {
		throw std::runtime_error(std::string("Invalid JSON config: ") +
								 error.what());
	}
}
} // namespace

FirewallBundle parseFirewallBundle(const std::string &content) {
	const Json document = parseJson(content);
	if (!document.is_object() || !document.contains("format") ||
		!document["format"].is_string() ||
		document["format"] != "archangel-firewall-config" ||
		!document.contains("version") ||
		!document["version"].is_number_integer() ||
		!document.contains("firewall") || !document["firewall"].is_object() ||
		document.size() != 3) {
		throw std::runtime_error("Firewall bundle must use format "
								 "archangel-firewall-config version 1");
	}

	const int version = document["version"].get<int>();
	if (version != 1) {
		throw std::runtime_error("Firewall bundle must use format "
								 "archangel-firewall-config version 1");
	}

	const Json &firewall = document["firewall"];
	if (!firewall.contains("other_ruleset") ||
		!firewall.contains("archangel_rules") || firewall.size() != 2 ||
		!firewall["archangel_rules"].is_array()) {
		throw std::runtime_error(
			"Version 1 firewall bundle requires firewall.other_ruleset and "
			"firewall.archangel_rules");
	}

	Json otherRuleset	= parseRuleset(firewall["other_ruleset"],
									   "Config firewall.other_ruleset");
	Json archangelRules = firewall["archangel_rules"];
	for (const Json &entry : otherRuleset["nftables"]) {
		if (isArchangelRule(entry)) {
			throw std::runtime_error(
				"Archangel-managed rules must be in firewall.archangel_rules");
		}
	}
	for (const Json &entry : archangelRules) {
		if (!isArchangelRule(entry)) {
			throw std::runtime_error("Each firewall.archangel_rules entry must "
									 "be an Archangel-marked rule");
		}
	}

	Json combined = otherRuleset;
	for (const Json &entry : archangelRules) {
		combined["nftables"].push_back(entry);
	}
	return {combined.dump(), archangelRules.dump()};
}

FirewallBundleImportMode
resolveFirewallBundleImportMode(const std::string &mode) {
	if (mode == "merge") {
		return FirewallBundleImportMode::Merge;
	}
	if (mode == "replace-all") {
		return FirewallBundleImportMode::ReplaceAll;
	}
	if (mode == "replace") {
		return FirewallBundleImportMode::ReplaceArchangel;
	}
	throw std::runtime_error("Unsupported config import mode");
}

std::string serializeFirewallBundle(const std::string &ruleset) {
	const Json documentRuleset = parseRuleset(parseJson(ruleset), "Ruleset");
	Json	   otherRuleset{
			  {"nftables", Json::array()}
	 };
	Json archangelRules = Json::array();
	for (const Json &entry : documentRuleset["nftables"]) {
		if (isArchangelRule(entry)) {
			archangelRules.push_back(entry);
		} else {
			otherRuleset["nftables"].push_back(entry);
		}
	}
	Json firewall{
		{	 "other_ruleset",	  std::move(otherRuleset)},
		{"archangel_rules", std::move(archangelRules)}
	  };

	return Json{
			   {	"format", "archangel-firewall-config"},
			   { "version",						   1},
			   {"firewall",			std::move(firewall)}
	}
			   .dump(2) +
		   "\n";
}
