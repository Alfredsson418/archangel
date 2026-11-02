#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace Firewall {

/**
 * @brief Thrown when a firewall backend rejects a rule or rule target as
 * invalid, as opposed to failing to apply it.
 *
 * The message describes the invalid field without echoing its value and is
 * safe to return to API callers.
 */
class InvalidRuleError : public std::invalid_argument {
  public:
	using std::invalid_argument::invalid_argument;
};

/**
 * @brief Backend-neutral description of a rule to add.
 *
 * Optional fields left unset do not constrain the rule. At least one match is
 * required: a protocol, address, destination port, interface, or connection
 * state.
 */
struct RuleSpec {
	std::string family;
	std::string table;
	std::string chain;
	// tcp, udp, icmp, or icmpv6. A destination port requires tcp or udp.
	std::optional<std::string> protocol;
	// One address, or one subnet in CIDR form with no host bits set.
	std::optional<std::string> source_address;
	std::optional<std::string> destination_address;
	std::optional<std::uint16_t> destination_port;
	// Last port of a range starting at destination_port.
	std::optional<std::uint16_t> destination_port_end;
	std::optional<std::string>	 input_interface;
	std::optional<std::string>	 output_interface;
	// Any of new, established, related, and invalid.
	std::vector<std::string> connection_states;
	std::string				 action;
};

struct Statistics {
	std::uint64_t						 total_rules  = 0;
	std::uint64_t						 total_tables = 0;
	std::uint64_t						 total_chains = 0;
	std::map<std::string, std::uint64_t> rules_by_family;
	std::map<std::string, std::uint64_t> rules_by_protocol;
	std::map<std::string, std::uint64_t> rules_by_verdict;
};

class Backend {
  public:
	/** @brief Destroys the backend through the interface. */
	virtual ~Backend() = default;

	/**
	 * @brief Returns the active firewall ruleset in the backend's JSON format.
	 * @return The serialized ruleset JSON.
	 */
	virtual std::string listRules() = 0;

	/**
	 * @brief Summarizes tables, chains, rules, protocols, and verdicts.
	 * @return Aggregated statistics for the active ruleset.
	 */
	virtual Statistics getStatistics() = 0;

	/**
	 * @brief Adds a validated rule to the selected firewall backend.
	 * @param rule Structured description of the rule to add.
	 * @return No value.
	 * @throws InvalidRuleError If the backend rejects the rule as invalid.
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
	 * @throws InvalidRuleError If the target is invalid.
	 * @throws std::exception If deletion fails.
	 */
	virtual void deleteRule(const std::string &family, const std::string &table,
							const std::string &chain, std::uint64_t handle) = 0;
};

} // namespace Firewall
