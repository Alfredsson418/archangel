#pragma once

#include "firewall/providers/firewall_config_provider.hpp"
#include <string>

inline constexpr char ARCHANGEL_RULE_COMMENT[] = "archangel-managed";

struct FirewallConfig {
	std::string ruleset;
	std::string archangel_rules;
};

/**
 * @brief Parses and validates a version 1 firewall configuration bundle.
 * @param content Complete firewall bundle JSON text.
 * @return Validated serialized ruleset sections.
 * @throws std::runtime_error If the schema or any required field is invalid.
 */
FirewallConfig parseFirewallConfig(const std::string &content);

/**
 * @brief Resolves a CLI import mode for a version 1 firewall bundle.
 * @param mode Requested mode: merge, replace, or replace-all.
 * @return The operation to apply to the firewall.
 * @throws std::runtime_error If the mode is unsupported.
 */
FirewallConfigImportMode
resolveFirewallConfigImportMode(const std::string &mode);

/**
 * @brief Serializes a native nftables ruleset firewall bundle.
 * @param ruleset Complete native nftables ruleset JSON.
 * @return Pretty-printed versioned firewall bundle with a trailing newline.
 * @throws std::runtime_error If the ruleset is invalid.
 */
std::string serializeFirewallConfig(const std::string &ruleset);
