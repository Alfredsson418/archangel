#include "firewall/bundle.hpp"
#include "test_support.hpp"
#include "json/json.hpp"

#include <stdexcept>
#include <string>

namespace {
using Json = nlohmann::json;

const std::string fullRuleset = R"({
	"nftables": [
		{"metainfo": {"json_schema_version": 1}},
		{"table": {"family": "inet", "name": "filter"}},
		{"chain": {"family": "inet", "table": "filter", "name": "input"}},
		{"rule": {"family": "inet", "table": "filter", "chain": "input",
			"handle": 1, "expr": [{"accept": null}]}},
		{"rule": {"family": "inet", "table": "filter", "chain": "input",
			"handle": 2, "comment": "archangel-managed",
			"expr": [{"drop": null}]}}
	]
})";

void roundTripsV2ManagedAndExternalSections() {
	const std::string encoded  = Firewall::serializeBundle(fullRuleset);
	const Json		  document = Json::parse(encoded);
	TestSupport::require(
		document["format"] == "archangel-firewall-config",
		"firewall exports should use the firewall-specific format name");
	TestSupport::require(document["version"] == 1,
						 "firewall export should use version 1");
	TestSupport::require(!document.contains("server"),
						 "firewall bundles must not contain listener settings");
	TestSupport::require(
		document["firewall"]["other_ruleset"]["nftables"].size() == 4,
		"v2 external section should contain non-owned objects and rules");
	TestSupport::require(document["firewall"]["archangel_rules"].size() == 1,
						 "v2 managed section should contain marked rules only");

	const Firewall::Bundle config	= Firewall::parseBundle(encoded);
	const Json			   combined = Json::parse(config.ruleset);
	TestSupport::require(combined["nftables"].size() == 5,
						 "combined ruleset should reconstruct every object");
	TestSupport::require(
		Json::parse(config.archangel_rules).size() == 1,
		"managed rules should remain separately available for replacement");
}

void rejectsIncorrectOwnershipSections() {
	Json document = Json::parse(Firewall::serializeBundle(fullRuleset));
	document["firewall"]["archangel_rules"].push_back(Json{
		{"rule", {{"family", "inet"}, {"comment", "external"}}}
	   });
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Firewall::parseBundle(document.dump()); },
		"unmarked rules must not be accepted as Archangel-owned");

	document = Json::parse(Firewall::serializeBundle(fullRuleset));
	document["firewall"]["other_ruleset"]["nftables"].push_back(
		document["firewall"]["archangel_rules"][0]);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Firewall::parseBundle(document.dump()); },
		"marked rules must not appear in the external section");
}

void rejectsUnsupportedConfigVersions() {
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			Firewall::parseBundle(
				R"({"format":"archangel-firewall-config","version":2,"firewall":{"other_ruleset":{"nftables":[]},"archangel_rules":[]}})");
		},
		"the former version 2 firewall bundle must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			Firewall::parseBundle(
				R"({"format":"archangel-firewall-config","version":1,"server":{"interface":"127.0.0.1","port":8080},"firewall":{"other_ruleset":{"nftables":[]},"archangel_rules":[]}})");
		},
		"firewall bundles must reject listener settings");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			Firewall::parseBundle(
				R"({"format":"archangel-backend-config","version":2,"server":{"interface":"127.0.0.1","port":8080},"firewall":{"other_ruleset":{"nftables":[]},"archangel_rules":[]}})");
		},
		"the ambiguous old format name must not be accepted");
}

void resolvesImportModes() {
	TestSupport::require(Firewall::resolveBundleImportMode("replace") ==
							 Firewall::BundleImportMode::ReplaceArchangel,
						 "replace must target only marked Archangel rules");
	TestSupport::require(Firewall::resolveBundleImportMode("replace-all") ==
							 Firewall::BundleImportMode::ReplaceAll,
						 "replace-all must explicitly target the full ruleset");
	TestSupport::require(Firewall::resolveBundleImportMode("merge") ==
							 Firewall::BundleImportMode::Merge,
						 "merge must be supported");
	TestSupport::requireThrows<std::runtime_error>(
		[] { Firewall::resolveBundleImportMode("invalid"); },
		"unknown import modes should fail");
}
} // namespace

void runFirewallBundleTests() {
	roundTripsV2ManagedAndExternalSections();
	rejectsIncorrectOwnershipSections();
	rejectsUnsupportedConfigVersions();
	resolvesImportModes();
}
