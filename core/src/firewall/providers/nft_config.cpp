#include "../../../include/firewall/providers/nft.hpp"
#include "../../../include/firewall/config.hpp"

#include <stdexcept>

std::string Nftables::exportFirewallConfig() {
	return serializeFirewallConfig(exportRuleset());
}

void Nftables::importFirewallConfig(const std::string &bundle,
									FirewallConfigImportMode mode) {
	const FirewallConfig config = parseFirewallConfig(bundle);
	switch (mode) {
	case FirewallConfigImportMode::Merge:
		importRuleset(config.ruleset, false);
		return;
	case FirewallConfigImportMode::ReplaceArchangel:
		replaceArchangelRuleset(config.archangel_rules);
		return;
	case FirewallConfigImportMode::ReplaceAll:
		importRuleset(config.ruleset, true);
		return;
	}
	throw std::runtime_error("Unsupported firewall config import mode");
}
