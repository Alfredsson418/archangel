#include "../../include/firewall/nft.hpp"

Nftables::Nftables() : context_(nullptr) {
	context_ = nft_ctx_new(0);

	if (context_ == nullptr) {
		throw std::runtime_error("Failed to create nftables context");
	}

	// Ask libnftables to return JSON instead of human-readable output.
	nft_ctx_output_set_flags(context_, nft_ctx_output_get_flags(context_) |
										   NFT_CTX_OUTPUT_JSON);

	// Store output internally so we can retrieve it afterwards.
	if (nft_ctx_buffer_output(context_) != 0) {
		nft_ctx_free(context_);
		context_ = nullptr;

		throw std::runtime_error("Failed to enable nftables output buffering");
	}
}

Nftables::~Nftables() {
	if (context_ != nullptr) {
		nft_ctx_free(context_);
	}
}

std::string Nftables::listRules() {
	// Clear any output left from a previous command.
	nft_ctx_unbuffer_output(context_);

	if (nft_ctx_buffer_output(context_) != 0) {
		throw std::runtime_error("Failed to enable nftables output buffering");
	}

	const int result = nft_run_cmd_from_buffer(context_, "list ruleset");

	if (result != 0) {
		const char *error = nft_ctx_get_error_buffer(context_);

		if (error != nullptr) {
			throw std::runtime_error(error);
		}

		throw std::runtime_error("Failed to list nftables rules");
	}

	const char *output = nft_ctx_get_output_buffer(context_);

	if (output == nullptr) {
		return "{}";
	}

	return std::string(output);
}
