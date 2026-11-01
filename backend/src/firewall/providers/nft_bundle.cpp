#include "firewall/bundle.hpp"
#include "firewall/providers/nft.hpp"

#include <stdexcept>

namespace Firewall {

std::string Nftables::exportBundle() {
	return serializeBundle(exportRuleset());
}

void Nftables::importBundle(const std::string &bundle, BundleImportMode mode) {
	const Bundle config = parseBundle(bundle);
	switch (mode) {
	case BundleImportMode::Merge:
		importRuleset(config.ruleset, false);
		return;
	case BundleImportMode::ReplaceArchangel:
		replaceArchangelRuleset(config.archangel_rules);
		return;
	case BundleImportMode::ReplaceAll:
		importRuleset(config.ruleset, true);
		return;
	}
	throw std::runtime_error("Unsupported firewall config import mode");
}

} // namespace Firewall
