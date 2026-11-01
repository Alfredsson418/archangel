#pragma once

#include <string>

enum class FirewallConfigImportMode { Merge, ReplaceArchangel, ReplaceAll };

/**
 * @brief Optional capability for importing and exporting native firewall
 * configuration bundles.
 *
 * A Firewall implementation that cannot represent the bundle format need not
 * implement this interface.
 */
class FirewallConfigProvider {
  public:
	virtual ~FirewallConfigProvider() = default;

	/**
	 * @brief Exports the backend's complete firewall configuration bundle.
	 * @return Versioned firewall bundle JSON.
	 * @throws std::exception If the active configuration cannot be exported.
	 */
	virtual std::string exportFirewallConfig() = 0;

	/**
	 * @brief Validates and applies a firewall configuration bundle.
	 * @param bundle Versioned firewall bundle JSON.
	 * @param mode Explicit merge or replacement operation.
	 * @return No value.
	 * @throws std::exception If the bundle is invalid or cannot be applied.
	 */
	virtual void importFirewallConfig(const std::string		  &bundle,
									  FirewallConfigImportMode mode) = 0;
};
