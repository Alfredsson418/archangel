#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
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
	std::optional<std::string>	 source_address;
	std::optional<std::string>	 destination_address;
	std::optional<std::uint16_t> destination_port;
	// Last port of a range starting at destination_port.
	std::optional<std::uint16_t> destination_port_end;
	std::optional<std::string>	 input_interface;
	std::optional<std::string>	 output_interface;
	// Any of new, established, related, and invalid.
	std::vector<std::string> connection_states;
	std::string				 action;
};

/** @brief Adds a rule at the end of its chain, marked as Archangel-managed. */
struct AddRuleChange {
	RuleSpec rule;
	// Lets a later SetRuleOrderChange in the same list place this rule, which
	// has no handle yet. May be empty.
	std::string id;
};

/** @brief Deletes a rule, identified by its chain and handle. */
struct DeleteRuleChange {
	std::string	  family;
	std::string	  table;
	std::string	  chain;
	std::uint64_t handle = 0;
};

/**
 * @brief Replaces a rule in place, keeping its position, handle, and comment.
 *
 * rule.family, rule.table, and rule.chain identify the existing rule's chain.
 */
struct ReplaceRuleChange {
	RuleSpec	  rule;
	std::uint64_t handle = 0;
};

/**
 * @brief Sets the complete order of a chain's rules.
 *
 * Entries are handles of existing rules or IDs of rules added earlier in the
 * same list. They must list exactly the rules the chain has at that point.
 * Rules that move get new handles, and a chain can't also be renamed or deleted
 * in the same list.
 */
struct SetRuleOrderChange {
	std::string											  family;
	std::string											  table;
	std::string											  chain;
	std::vector<std::variant<std::uint64_t, std::string>> order;
};

/** @brief The hook a base chain attaches to. */
struct BaseChain {
	std::string	 type;
	std::string	 hook;
	std::int32_t priority = 0;
	std::string	 policy;
};

/** @brief Creates a chain, which is a base chain if base is set. */
struct CreateChainChange {
	std::string				 family;
	std::string				 table;
	std::string				 name;
	std::optional<BaseChain> base;
};

/**
 * @brief Renames a chain. Rules that jump to it follow the new name.
 *
 * nftables applies a rename at the end of a transaction, so rules can't be
 * changed under either name later in the same list.
 */
struct RenameChainChange {
	std::string family;
	std::string table;
	std::string name;
	std::string new_name;
};

/** @brief Changes a base chain's policy. */
struct SetChainPolicyChange {
	std::string family;
	std::string table;
	std::string name;
	std::string policy;
};

/** @brief Deletes a chain and any rules in it. */
struct DeleteChainChange {
	std::string family;
	std::string table;
	std::string name;
};

/** @brief Creates a table. */
struct CreateTableChange {
	std::string family;
	std::string name;
};

/** @brief Deletes a table and everything in it. */
struct DeleteTableChange {
	std::string family;
	std::string name;
};

/** @brief Turns enforcement of a table's rules on or off. */
struct SetTableEnabledChange {
	std::string family;
	std::string name;
	bool		enabled = true;
};

using Change =
	std::variant<AddRuleChange, DeleteRuleChange, ReplaceRuleChange,
				 SetRuleOrderChange, CreateChainChange, RenameChainChange,
				 SetChainPolicyChange, DeleteChainChange, CreateTableChange,
				 DeleteTableChange, SetTableEnabledChange>;

/**
 * @brief A chain's state when it was reviewed.
 *
 * The revision covers the chain's definition and its rules and handles, but not
 * counters, which change with traffic. Callers treat it as opaque text.
 */
struct ChainRevision {
	std::string family;
	std::string table;
	std::string chain;
	std::string revision;
};

/**
 * @brief Changes to apply together, all or none.
 *
 * Every existing chain a change touches must be listed in expected, so that a
 * change is refused if its chain has changed since it was reviewed. A change to
 * a table touches all of its chains.
 */
struct ChangeSet {
	std::vector<ChainRevision> expected;
	std::vector<Change>		   changes;
};

/**
 * @brief Thrown when a chain no longer matches the revision a change expected.
 *
 * Nothing has been applied. The message is safe to return to API callers.
 */
class ChangeConflictError : public std::runtime_error {
  public:
	using std::runtime_error::runtime_error;
};

/**
 * @brief Thrown when the firewall rejects a change in a change set.
 *
 * Nothing has been applied. The message is safe to return to API callers.
 */
class ChangeRejectedError : public std::runtime_error {
  public:
	/**
	 * @brief Creates the error for one change.
	 * @param index Position of the rejected change in the change set.
	 * @param message Safe description of the problem.
	 */
	ChangeRejectedError(std::size_t index, const std::string &message)
		: std::runtime_error(message), index_(index) {}

	/** @brief Gets the position of the rejected change.
	 * @return Zero-based index into ChangeSet::changes.
	 */
	std::size_t index() const noexcept { return index_; }

  private:
	std::size_t index_;
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

	/**
	 * @brief Reports the current revision of every chain.
	 * @return One revision per chain.
	 * @throws std::exception If the ruleset cannot be read.
	 */
	virtual std::vector<ChainRevision> chainRevisions() = 0;

	/**
	 * @brief Reports whether a change set would apply, without applying it.
	 *
	 * Passing this check does not guarantee that applying later succeeds.
	 *
	 * @param changes Changes to check.
	 * @return No value.
	 * @throws InvalidRuleError If the change set is malformed.
	 * @throws ChangeConflictError If a chain has changed.
	 * @throws ChangeRejectedError If the firewall rejects a change.
	 * @throws std::exception If the check cannot be performed.
	 */
	virtual void checkChanges(const ChangeSet &changes) = 0;

	/**
	 * @brief Applies a change set in one transaction, all or none.
	 * @param changes Changes to apply.
	 * @return No value.
	 * @throws InvalidRuleError If the change set is malformed.
	 * @throws ChangeConflictError If a chain has changed.
	 * @throws ChangeRejectedError If the firewall rejects a change.
	 * @throws std::exception If the changes cannot be applied.
	 */
	virtual void applyChanges(const ChangeSet &changes) = 0;
};

} // namespace Firewall
