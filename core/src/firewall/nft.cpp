#include "../../include/firewall/nft.hpp"
#include "../../include/error.hpp"
#include "../../include/logger.hpp"
#include "../../lib/json/json.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <sstream>

namespace {

bool isIdentifier(const std::string &value) {
	const auto isAlpha = [](unsigned char character) {
		return (character >= 'a' && character <= 'z') ||
			   (character >= 'A' && character <= 'Z');
	};
	const auto isDigit = [](unsigned char character) {
		return character >= '0' && character <= '9';
	};

	if (value.empty() || value.size() > 64 ||
		!(isAlpha(static_cast<unsigned char>(value.front())) ||
		  value.front() == '_')) {
		return false;
	}

	for (const unsigned char character : value) {
		if (!(isAlpha(character) || isDigit(character) || character == '_' ||
			  character == '-')) {
			return false;
		}
	}
	return true;
}

bool isIpv4Address(const std::string &address) {
	in_addr parsed{};
	return inet_pton(AF_INET, address.c_str(), &parsed) == 1;
}

bool isIpv6Address(const std::string &address) {
	in6_addr parsed{};
	return inet_pton(AF_INET6, address.c_str(), &parsed) == 1;
}

void validateAddress(const std::string &family, const std::string &address) {
	const bool ipv4 = isIpv4Address(address);
	const bool ipv6 = isIpv6Address(address);
	if ((!ipv4 && !ipv6) || (family == "ip" && !ipv4) ||
		(family == "ip6" && !ipv6)) {
		throw ValidationError("An address is invalid for the selected family");
	}
}

void validateRule(const RuleSpec &rule) {
	if (rule.family != "ip" && rule.family != "ip6" && rule.family != "inet") {
		throw ValidationError("family must be ip, ip6, or inet");
	}
	if (!isIdentifier(rule.table) || !isIdentifier(rule.chain)) {
		throw ValidationError(
			"table and chain must be valid nftables identifiers");
	}
	if (rule.protocol != "tcp" && rule.protocol != "udp") {
		throw ValidationError("protocol must be tcp or udp");
	}
	if (rule.action != "accept" && rule.action != "drop" &&
		rule.action != "reject") {
		throw ValidationError("action must be accept, drop, or reject");
	}
	if (!rule.source_address && !rule.destination_address &&
		!rule.destination_port) {
		throw ValidationError(
			"at least one address or destination port match is required");
	}
	if (rule.source_address) {
		validateAddress(rule.family, *rule.source_address);
	}
	if (rule.destination_address) {
		validateAddress(rule.family, *rule.destination_address);
	}
}

std::string addressMatch(const std::string &address, const char *direction) {
	return std::string(isIpv4Address(address) ? "ip " : "ip6 ") + direction +
		   " " + address;
}

} // namespace

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
	std::lock_guard<std::mutex> lock(mutex_);
	execute("list ruleset");

	const char *output = nft_ctx_get_output_buffer(context_);
	return output == nullptr ? "{}" : std::string(output);
}

FirewallStatistics Nftables::getStatistics() {
	using Json		   = nlohmann::json;
	const Json ruleset = Json::parse(listRules());
	if (!ruleset.is_object() || !ruleset.contains("nftables") ||
		!ruleset["nftables"].is_array()) {
		throw std::runtime_error("Invalid nftables ruleset JSON");
	}

	FirewallStatistics statistics;
	for (const Json &entry : ruleset["nftables"]) {
		if (!entry.is_object()) {
			continue;
		}
		if (entry.contains("table")) {
			++statistics.total_tables;
		}
		if (entry.contains("chain")) {
			++statistics.total_chains;
		}
		if (!entry.contains("rule") || !entry["rule"].is_object()) {
			continue;
		}

		const Json &rule = entry["rule"];
		++statistics.total_rules;
		const std::string family = rule.value("family", "other");
		++statistics.rules_by_family[family];

		std::string protocol   = "other";
		std::string verdict	   = "other";
		const auto	expression = rule.find("expr");
		if (expression != rule.end() && expression->is_array()) {
			for (const Json &statement : *expression) {
				if (!statement.is_object()) {
					continue;
				}
				for (const char *candidate : {"accept", "drop", "reject"}) {
					if (statement.contains(candidate)) {
						verdict = candidate;
						break;
					}
				}

				const auto match = statement.find("match");
				if (match == statement.end() || !match->is_object()) {
					continue;
				}
				const auto left	 = match->find("left");
				const auto right = match->find("right");
				if (left == match->end() || !left->is_object() ||
					right == match->end() || !right->is_string()) {
					continue;
				}
				const auto meta = left->find("meta");
				if (meta != left->end() && meta->is_object() &&
					meta->value("key", std::string()) == "l4proto") {
					const std::string candidate = right->get<std::string>();
					if (candidate == "tcp" || candidate == "udp") {
						protocol = candidate;
					}
				}
			}
		}
		++statistics.rules_by_protocol[protocol];
		++statistics.rules_by_verdict[verdict];
	}

	return statistics;
}

void Nftables::addRule(const RuleSpec &rule) {
	validateRule(rule);

	std::ostringstream command;
	command << "add rule " << rule.family << ' ' << rule.table << ' '
			<< rule.chain;
	if (rule.source_address) {
		command << ' ' << addressMatch(*rule.source_address, "saddr");
	}
	if (rule.destination_address) {
		command << ' ' << addressMatch(*rule.destination_address, "daddr");
	}
	command << " meta l4proto " << rule.protocol;
	if (rule.destination_port) {
		command << ' ' << rule.protocol << " dport " << *rule.destination_port;
	}
	command << ' ' << rule.action;

	std::lock_guard<std::mutex> lock(mutex_);
	execute(command.str());
	Logger::Firewall::log("Added a " + rule.protocol + " rule to " +
						  rule.family + " " + rule.table + " " + rule.chain);
}

void Nftables::deleteRule(const std::string &family, const std::string &table,
						  const std::string &chain, std::uint64_t handle) {
	if ((family != "ip" && family != "ip6" && family != "inet") ||
		!isIdentifier(table) || !isIdentifier(chain) || handle == 0) {
		throw ValidationError(
			"family, table, chain, or rule handle is invalid");
	}

	const std::string command = "delete rule " + family + " " + table + " " +
								chain + " handle " + std::to_string(handle);
	std::lock_guard<std::mutex> lock(mutex_);
	execute(command);
	Logger::Firewall::log("Deleted rule handle " + std::to_string(handle) +
						  " from " + family + " " + table + " " + chain);
}

void Nftables::execute(const std::string &command) {
	// Clear any output left from a previous command.
	nft_ctx_unbuffer_output(context_);

	if (nft_ctx_buffer_output(context_) != 0) {
		throw std::runtime_error("Failed to enable nftables output buffering");
	}

	const int result = nft_run_cmd_from_buffer(context_, command.c_str());

	if (result != 0) {
		const char *error = nft_ctx_get_error_buffer(context_);

		if (error != nullptr) {
			throw std::runtime_error(error);
		}

		throw std::runtime_error("Failed to execute nftables command");
	}
}
