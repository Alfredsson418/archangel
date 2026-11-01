#pragma once

#include <cstddef>
#include <string>

namespace Firewall {

struct ArchangelRulesReplacement {
	std::string transaction;
	std::size_t removed;
	std::size_t added;
};

/**
 * @brief Builds an atomic transaction replacing only marked Archangel rules.
 * @param activeRuleset Current complete nftables JSON ruleset.
 * @param managedRules JSON array of replacement Archangel rule objects.
 * @return Serialized nftables transaction and its removal/addition counts.
 * @throws std::runtime_error If either input is malformed or an owned rule
 * cannot be safely deleted.
 */
ArchangelRulesReplacement
buildArchangelRulesReplacement(const std::string &activeRuleset,
							   const std::string &managedRules);

} // namespace Firewall
