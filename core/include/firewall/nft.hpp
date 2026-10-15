#pragma once

#include "firewall.hpp"
#include <mutex>
#include <nftables/libnftables.h>
#include <stdexcept>
#include <string>

class Nftables : public Firewall {
  public:
	Nftables();
	~Nftables() override;

	Nftables(const Nftables &)			  = delete;
	Nftables &operator=(const Nftables &) = delete;

	std::string		   listRules() override;
	FirewallStatistics getStatistics() override;
	void			   addRule(const RuleSpec &rule) override;
	void deleteRule(const std::string &family, const std::string &table,
					const std::string &chain, std::uint64_t handle) override;

  private:
	void			execute(const std::string &command);
	std::mutex		mutex_;
	struct nft_ctx *context_;
};
