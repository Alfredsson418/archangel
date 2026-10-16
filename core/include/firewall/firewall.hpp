#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

struct RuleSpec {
	std::string					 family;
	std::string					 table;
	std::string					 chain;
	std::string					 protocol;
	std::optional<std::string>	 source_address;
	std::optional<std::string>	 destination_address;
	std::optional<std::uint16_t> destination_port;
	std::string					 action;
};

struct FirewallStatistics {
	std::uint64_t						 total_rules  = 0;
	std::uint64_t						 total_tables = 0;
	std::uint64_t						 total_chains = 0;
	std::map<std::string, std::uint64_t> rules_by_family;
	std::map<std::string, std::uint64_t> rules_by_protocol;
	std::map<std::string, std::uint64_t> rules_by_verdict;
};

class Firewall {
  public:
	/** @brief Destroys the backend through the interface. */
	virtual ~Firewall() = default;

	/**
	 * @brief Returns the active firewall ruleset in the backend's JSON format.
	 * @return The serialized ruleset JSON.
	 */
	virtual std::string listRules() = 0;

	/**
	 * @brief Summarizes tables, chains, rules, protocols, and verdicts.
	 * @return Aggregated statistics for the active ruleset.
	 */
	virtual FirewallStatistics getStatistics() = 0;

	/**
	 * @brief Adds a validated rule to the selected firewall backend.
	 * @param rule Structured description of the rule to add.
	 * @return No value.
	 * @throws std::exception If the rule cannot be applied.
	 */
	virtual void addRule(const RuleSpec &rule) = 0;

	/**
	 * @brief Deletes a rule from the selected backend by its numeric handle.
	 * @param family Firewall address family.
	 * @param table Table containing the rule.
	 * @param chain Chain containing the rule.
	 * @param handle Positive backend rule handle.
	 * @return No value.
	 * @throws std::exception If the target is invalid or deletion fails.
	 */
	virtual void deleteRule(const std::string &family, const std::string &table,
							const std::string &chain, std::uint64_t handle) = 0;
};
