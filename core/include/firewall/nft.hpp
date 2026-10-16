#pragma once

#include "firewall.hpp"
#include <mutex>
#include <nftables/libnftables.h>
#include <stdexcept>
#include <string>

class Nftables : public Firewall {
  public:
	/**
	 * @brief Creates an nftables context configured for buffered JSON output.
	 * @throws std::runtime_error If the nftables context cannot be initialized.
	 */
	Nftables();

	/** @brief Releases the owned libnftables context. */
	~Nftables() override;

	Nftables(const Nftables &)			  = delete;
	Nftables &operator=(const Nftables &) = delete;

	/**
	 * @brief Implements Firewall::listRules.
	 * @return Serialized nftables ruleset JSON.
	 */
	std::string listRules() override;

	/**
	 * @brief Exports the complete active nftables ruleset as nftables JSON.
	 * @return Serialized native nftables JSON ruleset.
	 * @throws std::runtime_error If the ruleset cannot be read.
	 */
	std::string exportRuleset();

	/**
	 * @brief Applies a native nftables JSON ruleset through libnftables.
	 * @param ruleset Serialized native nftables JSON ruleset.
	 * @param replaceAll Whether to flush the entire active ruleset first.
	 * @return No value.
	 * @throws std::runtime_error If the configuration cannot be applied.
	 */
	void importRuleset(const std::string &ruleset, bool replaceAll);

	/**
	 * @brief Implements Firewall::getStatistics.
	 * @return Aggregated statistics for the active ruleset.
	 */
	FirewallStatistics getStatistics() override;

	/**
	 * @brief Implements Firewall::addRule using libnftables.
	 * @param rule Structured rule description.
	 * @return No value.
	 * @throws ApiError If the rule is invalid; std::exception if nftables
	 * fails.
	 */
	void addRule(const RuleSpec &rule) override;

	/**
	 * @brief Implements Firewall::deleteRule using libnftables.
	 * @param family Firewall address family.
	 * @param table Table containing the rule.
	 * @param chain Chain containing the rule.
	 * @param handle Positive nftables rule handle.
	 * @return No value.
	 * @throws ApiError If the target is invalid; std::exception if nftables
	 * fails.
	 */
	void deleteRule(const std::string &family, const std::string &table,
					const std::string &chain, std::uint64_t handle) override;

  private:
	/**
	 * @brief Executes one command through the owned libnftables context.
	 * @param command Validated nftables command string.
	 * @return No value.
	 * @throws std::runtime_error If buffering or command execution fails.
	 */
	void			execute(const std::string &command);
	std::mutex		mutex_;
	struct nft_ctx *context_;
};
