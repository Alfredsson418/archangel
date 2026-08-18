#pragma once

#include <nftables/libnftables.h>
#include <stdexcept>
#include <string>

class Nftables {
  public:
	Nftables();
	~Nftables();

	Nftables(const Nftables &)			  = delete;
	Nftables &operator=(const Nftables &) = delete;

	std::string listRules();

  private:
	struct nft_ctx *context_;
};
