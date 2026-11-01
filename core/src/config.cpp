#include "../include/config.hpp"
#include "../lib/json/json.hpp"

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

BackendConfig parseBackendConfig(const std::string &content) {
	const Json document = parseJson(content);
	if (!document.is_object() || !document.contains("format") ||
		!document["format"].is_string() ||
		document["format"] != "archangel-backend-config" ||
		!document.contains("version") ||
		!document["version"].is_number_integer() ||
		!document.contains("server") || !document["server"].is_object() ||
		!document.contains("firewall") || !document["firewall"].is_object() ||
		document.size() != 4) {
		throw std::runtime_error(
			"Config must use format archangel-backend-config version 2");
	}

	const int version = document["version"].get<int>();
	if (version != 2) {
		throw std::runtime_error(
			"Config must use format archangel-backend-config version 2");
	}

	const Json &server = document["server"];
	if (!server.contains("interface") || !server["interface"].is_string() ||
		!server.contains("port") || !server["port"].is_number_integer() ||
		server.size() != 2) {
		throw std::runtime_error(
			"Config server requires a string interface and integer port");
	}
	const std::string interface = server["interface"].get<std::string>();
	const Json		 &port		= server["port"];
	if (port < 1 || port > 65535) {
		throw std::runtime_error("Config server interface or port is invalid");
	}
	const unsigned int portValue = port.get<unsigned int>();
	if (interface.empty() || interface.size() > 255 ||
		interface.find_first_of(" \t\r\n") != std::string::npos ||
		interface.find('\0') != std::string::npos) {
		throw std::runtime_error("Config server interface or port is invalid");
	}

	const Json &firewall = document["firewall"];
	if (!firewall.contains("other_ruleset") ||
		!firewall.contains("archangel_rules") || firewall.size() != 2 ||
		!firewall["archangel_rules"].is_array()) {
		throw std::runtime_error(
			"Version 2 config requires firewall.other_ruleset and "
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
	return {interface, static_cast<std::uint16_t>(portValue), combined.dump(),
			archangelRules.dump()};
}

BackendConfigImportMode
resolveBackendConfigImportMode(const std::string &mode) {
	if (mode == "merge") {
		return BackendConfigImportMode::Merge;
	}
	if (mode == "replace-all") {
		return BackendConfigImportMode::ReplaceAll;
	}
	if (mode == "replace") {
		return BackendConfigImportMode::ReplaceArchangel;
	}
	throw std::runtime_error("Unsupported config import mode");
}

std::string serializeBackendConfig(const std::string &interface,
								   std::uint16_t	  port,
								   const std::string &ruleset) {
	const Json documentRuleset = parseRuleset(parseJson(ruleset), "Ruleset");
	Json otherRuleset{{"nftables", Json::array()}};
	Json archangelRules = Json::array();
	for (const Json &entry : documentRuleset["nftables"]) {
		if (isArchangelRule(entry)) {
			archangelRules.push_back(entry);
		} else {
			otherRuleset["nftables"].push_back(entry);
		}
	}
	Json firewall{{"other_ruleset", std::move(otherRuleset)},
				  {"archangel_rules", std::move(archangelRules)}};

	return Json{
			   {  "format",					"archangel-backend-config"},
			   { "version",											2},
			   {  "server", {{"interface", interface}, {"port", port}}},
			   {"firewall",						   std::move(firewall)}
	}
			   .dump(2) +
		   "\n";
}
