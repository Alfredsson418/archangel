#include "firewall/bundle.hpp"
#include "firewall/providers/nft.hpp"

#include <stdexcept>

std::string Nftables::exportFirewallBundle() {
	return serializeFirewallBundle(exportRuleset());
}

void Nftables::importFirewallBundle(const std::string		&bundle,
									FirewallBundleImportMode mode) {
	const FirewallBundle config = parseFirewallBundle(bundle);
	switch (mode) {
	case FirewallBundleImportMode::Merge:
		importRuleset(config.ruleset, false);
		return;
	case FirewallBundleImportMode::ReplaceArchangel:
		replaceArchangelRuleset(config.archangel_rules);
		return;
	case FirewallBundleImportMode::ReplaceAll:
		importRuleset(config.ruleset, true);
		return;
	}
	throw std::runtime_error("Unsupported firewall config import mode");
}
