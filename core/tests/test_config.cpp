#include "../include/config.hpp"
#include "../lib/json/json.hpp"
#include "test_support.hpp"

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
	const std::string encoded =
		serializeBackendConfig("127.0.0.1", 8080, fullRuleset);
	const Json document = Json::parse(encoded);
	TestSupport::require(document["version"] == 2,
						 "v2 export should identify its format version");
	TestSupport::require(
		document["firewall"]["other_ruleset"]["nftables"].size() == 4,
		"v2 external section should contain non-owned objects and rules");
	TestSupport::require(document["firewall"]["archangel_rules"].size() == 1,
						 "v2 managed section should contain marked rules only");

	const BackendConfig config = parseBackendConfig(encoded);
	TestSupport::require(config.interface == "127.0.0.1" && config.port == 8080,
						 "server settings should round-trip");
	const Json combined = Json::parse(config.ruleset);
	TestSupport::require(combined["nftables"].size() == 5,
						 "combined ruleset should reconstruct every object");
	TestSupport::require(
		Json::parse(config.archangel_rules).size() == 1,
		"managed rules should remain separately available for replacement");
}

void rejectsIncorrectOwnershipSections() {
	Json document =
		Json::parse(serializeBackendConfig("127.0.0.1", 8080, fullRuleset));
	document["firewall"]["archangel_rules"].push_back(Json{
		{"rule", {{"family", "inet"}, {"comment", "external"}}}
	   });
	TestSupport::requireThrows<std::runtime_error>(
		[&] { parseBackendConfig(document.dump()); },
		"unmarked rules must not be accepted as Archangel-owned");

	document =
		Json::parse(serializeBackendConfig("127.0.0.1", 8080, fullRuleset));
	document["firewall"]["other_ruleset"]["nftables"].push_back(
		document["firewall"]["archangel_rules"][0]);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { parseBackendConfig(document.dump()); },
		"marked rules must not appear in the external section");
}

void rejectsUnsupportedConfigVersions() {
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseBackendConfig(
				R"({"format":"archangel-backend-config","version":1,"server":{"interface":"127.0.0.1","port":8080},"firewall":{"ruleset":{"nftables":[]}}})");
		},
		"v1 configs should no longer be accepted");
}

void resolvesImportModes() {
	TestSupport::require(
		resolveBackendConfigImportMode("replace") ==
			BackendConfigImportMode::ReplaceArchangel,
		"replace must target only marked Archangel rules");
	TestSupport::require(resolveBackendConfigImportMode("replace-all") ==
							 BackendConfigImportMode::ReplaceAll,
						 "replace-all must explicitly target the full ruleset");
	TestSupport::require(resolveBackendConfigImportMode("merge") ==
							 BackendConfigImportMode::Merge,
						 "merge must be supported");
	TestSupport::requireThrows<std::runtime_error>(
		[] { resolveBackendConfigImportMode("invalid"); },
		"unknown import modes should fail");
}
} // namespace

void runConfigTests() {
	roundTripsV2ManagedAndExternalSections();
	rejectsIncorrectOwnershipSections();
	rejectsUnsupportedConfigVersions();
	resolvesImportModes();
}
