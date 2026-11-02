#pragma once

#include "firewall/firewall.hpp"
#include "firewall/firewall_bundle_provider.hpp"

#include <string>

namespace Cli {

/**
 * @brief Requires a firewall backend to support bundle import and export.
 * @param firewall Backend to inspect.
 * @return The backend's firewall configuration provider.
 * @throws std::runtime_error If the backend lacks this optional capability.
 */
Firewall::BundleProvider &requireBundleProvider(Firewall::Backend &firewall);

/**
 * @brief Reads a bounded firewall configuration bundle from disk.
 * @param path Filesystem path to the bundle.
 * @return Bundle JSON text.
 * @throws std::runtime_error If the file cannot be read or exceeds 16 MiB.
 */
std::string readBundle(const std::string &path);

/**
 * @brief Writes a serialized firewall configuration bundle to disk.
 * @param path Filesystem path to write.
 * @param bundle Bundle JSON text, as returned by
 * Firewall::BundleProvider::exportBundle.
 * @return No value.
 * @throws std::runtime_error If file writing fails or the bundle exceeds
 * 16 MiB.
 */
void writeBundle(const std::string &path, const std::string &bundle);

} // namespace Cli
