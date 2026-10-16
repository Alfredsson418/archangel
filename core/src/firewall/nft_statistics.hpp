#pragma once

#include "../../include/firewall/firewall.hpp"
#include <string>

/**
 * @brief Extracts aggregate firewall counts from an nftables JSON ruleset.
 * @param ruleset Serialized nftables ruleset JSON.
 * @return Counts grouped by family, protocol, and verdict.
 * @throws std::exception If parsing fails or the expected nftables array is
 * absent.
 */
FirewallStatistics statisticsFromNftRuleset(const std::string &ruleset);
