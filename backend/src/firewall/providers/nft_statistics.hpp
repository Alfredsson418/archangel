#pragma once

#include "firewall/firewall.hpp"
#include <string>

namespace Firewall {

/**
 * @brief Extracts aggregate firewall counts from an nftables JSON ruleset.
 * @param ruleset Serialized nftables ruleset JSON.
 * @return Counts grouped by family, protocol, and verdict.
 * @throws std::exception If parsing fails or the expected nftables array is
 * absent.
 */
Statistics statisticsFromNftRuleset(const std::string &ruleset);

} // namespace Firewall
