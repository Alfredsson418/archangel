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
	virtual ~Firewall() = default;

	virtual std::string		   listRules()									= 0;
	virtual FirewallStatistics getStatistics()								= 0;
	virtual void			   addRule(const RuleSpec &rule)				= 0;
	virtual void deleteRule(const std::string &family, const std::string &table,
							const std::string &chain, std::uint64_t handle) = 0;
};
