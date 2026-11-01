#pragma once

#include "firewall/providers/firewall.hpp"
#include "firewall/providers/firewall_config_provider.hpp"

#include <string>

namespace FirewallConfigCommand {

/**
 * @brief Requires a firewall backend to support bundle import and export.
 * @param firewall Backend to inspect.
 * @return The backend's firewall configuration provider.
 * @throws std::runtime_error If the backend lacks this optional capability.
 */
FirewallConfigProvider &requireProvider(Firewall &firewall);

/**
 * @brief Reads a bounded firewall configuration bundle from disk.
 * @param path Filesystem path to the bundle.
 * @return Bundle JSON text.
 * @throws std::runtime_error If the file cannot be read or exceeds 16 MiB.
 */
std::string readBundle(const std::string &path);

/**
 * @brief Serializes and writes a firewall configuration bundle to disk.
 * @param path Filesystem path to write.
 * @param ruleset Complete native nftables ruleset JSON.
 * @return No value.
 * @throws std::runtime_error If serialization or file writing fails, or the
 * serialized bundle exceeds 16 MiB.
 */
void writeBundle(const std::string &path, const std::string &ruleset);

} // namespace FirewallConfigCommand
