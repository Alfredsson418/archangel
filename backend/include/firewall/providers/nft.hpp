#pragma once

#include "firewall/firewall.hpp"
#include "firewall/firewall_bundle_provider.hpp"
#include <cstddef>
#include <mutex>
#include <nftables/libnftables.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace Firewall {

class Nftables : public Backend, public BundleProvider {
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
	 * @brief Implements Backend::listRules.
	 * @return Serialized nftables ruleset JSON.
	 */
	std::string listRules() override;

	/**
	 * @brief Exports the active ruleset in the versioned firewall bundle.
	 * @return Versioned firewall bundle JSON.
	 * @throws std::exception If the active configuration cannot be exported.
	 */
	std::string exportBundle() override;

	/**
	 * @brief Validates and applies a versioned firewall bundle.
	 * @param bundle Versioned firewall bundle JSON.
	 * @param mode Explicit merge or replacement operation.
	 * @return No value.
	 * @throws std::exception If the bundle is invalid or cannot be applied.
	 */
	void importBundle(const std::string &bundle,
					  BundleImportMode	 mode) override;

	/**
	 * @brief Implements Backend::getStatistics.
	 * @return Aggregated statistics for the active ruleset.
	 */
	Statistics getStatistics() override;

	/**
	 * @brief Implements Backend::addRule using libnftables.
	 * @param rule Structured rule description.
	 * @return No value.
	 * @throws InvalidRuleError If the rule is invalid; std::exception if
	 * nftables fails.
	 */
	void addRule(const RuleSpec &rule) override;

	/**
	 * @brief Implements Backend::deleteRule using libnftables.
	 * @param family Firewall address family.
	 * @param table Table containing the rule.
	 * @param chain Chain containing the rule.
	 * @param handle Positive nftables rule handle.
	 * @return No value.
	 * @throws InvalidRuleError If the target is invalid; std::exception if
	 * nftables fails.
	 */
	void deleteRule(const std::string &family, const std::string &table,
					const std::string &chain, std::uint64_t handle) override;

	/**
	 * @brief Implements Backend::chainRevisions from the listed ruleset.
	 * @return One revision per chain.
	 * @throws std::exception If the ruleset cannot be read.
	 */
	std::vector<ChainRevision> chainRevisions() override;

	/**
	 * @brief Implements Backend::checkChanges using a libnftables dry run.
	 * @param changes Changes to check.
	 * @return No value.
	 * @throws InvalidRuleError, ChangeConflictError, or ChangeRejectedError as
	 * described by Backend::checkChanges.
	 */
	void checkChanges(const ChangeSet &changes) override;

	/**
	 * @brief Implements Backend::applyChanges in one nftables transaction.
	 * @param changes Changes to apply.
	 * @return No value.
	 * @throws InvalidRuleError, ChangeConflictError, or ChangeRejectedError as
	 * described by Backend::applyChanges.
	 */
	void applyChanges(const ChangeSet &changes) override;

  private:
	/**
	 * @brief Exports the complete active nftables ruleset as nftables JSON.
	 * @return Serialized native nftables JSON ruleset.
	 * @throws std::runtime_error If the ruleset cannot be read.
	 */
	std::string exportRuleset();

	/**
	 * @brief Lists the ruleset. The caller must hold mutex_.
	 * @return Serialized nftables ruleset JSON.
	 * @throws std::runtime_error If the ruleset cannot be read.
	 */
	std::string listUnlocked();

	/**
	 * @brief Finds the first change the firewall rejects. The caller must hold
	 * mutex_.
	 *
	 * A longer list fails whenever a shorter one does, so this bisects using
	 * dry runs. Nothing is applied.
	 *
	 * @param ruleset Current ruleset listing.
	 * @param changes Change set that the firewall rejected.
	 * @return Index of the first rejected change.
	 */
	std::size_t firstRejectedChange(const std::string &ruleset,
									const ChangeSet	  &changes);

	/**
	 * @brief Applies a native nftables JSON ruleset through libnftables.
	 * @param ruleset Serialized native nftables JSON ruleset.
	 * @param replaceAll Whether to flush the entire active ruleset first.
	 * @return No value.
	 * @throws std::runtime_error If the configuration cannot be applied.
	 */
	void importRuleset(const std::string &ruleset, bool replaceAll);

	/**
	 * @brief Atomically replaces only rules carrying the Archangel marker.
	 * @param rules Serialized nftables array containing only marked rule
	 * objects.
	 * @return No value.
	 * @throws std::runtime_error If the input or active ruleset is invalid or
	 * the transaction fails.
	 */
	void replaceArchangelRuleset(const std::string &rules);

	/**
	 * @brief Executes one command through the owned libnftables context.
	 * @param command Validated nftables command string.
	 * @return No value.
	 * @throws std::runtime_error If buffering or command execution fails.
	 */
	void execute(const std::string &command);

	/**
	 * @brief Executes an nftables JSON command document; callers must hold
	 * mutex_.
	 * @param commands Serialized document with an "nftables" command array.
	 * @return No value.
	 * @throws std::runtime_error If buffering or command execution fails.
	 */
	void			executeJson(const std::string &commands);
	std::mutex		mutex_;
	struct nft_ctx *context_;
};

} // namespace Firewall
