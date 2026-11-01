#pragma once

#include <cstdint>
#include <string>

inline constexpr char ARCHANGEL_RULE_COMMENT[] = "archangel-managed";

struct BackendConfig {
	std::string	  interface;
	std::uint16_t port;
	std::string	  ruleset;
	std::string	  archangel_rules;
};

enum class BackendConfigImportMode { Merge, ReplaceArchangel, ReplaceAll };

/**
 * @brief Parses and validates a version 2 backend configuration.
 * @param content Complete configuration JSON text.
 * @return Validated settings and serialized ruleset sections.
 * @throws std::runtime_error If the schema or any required field is invalid.
 */
BackendConfig parseBackendConfig(const std::string &content);

/**
 * @brief Resolves a CLI import mode for a version 2 backend config.
 * @param mode Requested mode: merge, replace, or replace-all.
 * @return The operation to apply to the firewall.
 * @throws std::runtime_error If the mode is unsupported.
 */
BackendConfigImportMode
resolveBackendConfigImportMode(const std::string &mode);

/**
 * @brief Serializes backend settings and a native nftables ruleset.
 * @param interface HTTP server bind address.
 * @param port HTTP server port.
 * @param ruleset Complete native nftables ruleset JSON.
 * @return Pretty-printed versioned configuration with a trailing newline.
 * @throws std::runtime_error If the ruleset is invalid.
 */
std::string serializeBackendConfig(const std::string &interface,
								   std::uint16_t	  port,
								   const std::string &ruleset);
