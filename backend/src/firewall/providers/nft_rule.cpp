#include "nft_rule.hpp"
#include "config/app_config.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>
#include <utility>

namespace Firewall::Detail {

namespace {

// Kept in this order so that equivalent rules produce identical statements.
constexpr std::array<const char *, Config::Limits::MAX_CONNECTION_STATES>
	CONNECTION_STATES = {"new", "established", "related", "invalid"};

struct ParsedAddress {
	std::string address;
	// Unset when the value covers one host, including /32 and /128, because
	// nftables reads those back as plain addresses.
	std::optional<int> prefix_length;
	bool			   ipv4;
};

/**
 * @brief Parses an address or CIDR subnet and rejects subnets with host bits.
 *
 * nftables would silently store 192.168.1.5/24 as 192.168.1.0/24, covering
 * addresses the caller did not type, so these are rejected rather than masked.
 *
 * @param value Address text supplied by the caller.
 * @return The parsed address.
 * @throws InvalidRuleError If the value is not a valid address or subnet.
 */
ParsedAddress parseAddress(const std::string &value) {
	const std::size_t slash	  = value.find('/');
	const std::string address = value.substr(0, slash);

	std::array<unsigned char, sizeof(in6_addr)> bytes{};
	const bool ipv4 = inet_pton(AF_INET, address.c_str(), bytes.data()) == 1;
	if (!ipv4 && inet_pton(AF_INET6, address.c_str(), bytes.data()) != 1) {
		throw InvalidRuleError("An address is invalid");
	}
	const int maxLength = ipv4 ? 32 : 128;
	if (slash == std::string::npos) {
		return {address, std::nullopt, ipv4};
	}

	const char *begin  = value.data() + slash + 1;
	const char *end	   = value.data() + value.size();
	int			length = -1;
	const auto	result = std::from_chars(begin, end, length);
	if (begin == end || result.ec != std::errc{} || result.ptr != end ||
		length < 0 || length > maxLength) {
		throw InvalidRuleError("A subnet prefix length is invalid");
	}

	for (int bit = length; bit < maxLength; ++bit) {
		if ((bytes[static_cast<std::size_t>(bit / 8)] >> (7 - bit % 8)) & 1) {
			throw InvalidRuleError(
				"A subnet must not have host bits set after its prefix");
		}
	}
	if (length == maxLength) {
		return {address, std::nullopt, ipv4};
	}
	return {address, length, ipv4};
}

/**
 * @brief Checks an interface name against what Linux allows.
 * @param name Candidate interface name.
 * @return True if the name has a valid length and characters.
 */
bool isInterfaceName(const std::string &name) {
	return !name.empty() &&
		   name.size() <= Config::Limits::MAX_INTERFACE_NAME_LENGTH &&
		   std::all_of(name.begin(), name.end(), [](unsigned char character) {
			   return (character >= 'a' && character <= 'z') ||
					  (character >= 'A' && character <= 'Z') ||
					  (character >= '0' && character <= '9') ||
					  character == '.' || character == '_' || character == '-';
		   });
}

/**
 * @brief Builds an nftables JSON match statement.
 * @param op Comparison operator, such as == or in.
 * @param left Expression to compare, such as a payload or meta selector.
 * @param right Value to compare against.
 * @return A JSON match statement.
 */
nlohmann::json match(const char *op, nlohmann::json left,
					 nlohmann::json right) {
	nlohmann::json statement;
	statement["op"]	   = op;
	statement["left"]  = std::move(left);
	statement["right"] = std::move(right);
	return nlohmann::json{
		{"match", std::move(statement)}
	   };
}

/**
 * @brief Builds a payload selector expression, such as ip saddr.
 * @param protocol Payload protocol, such as ip, ip6, or tcp.
 * @param field Payload field, such as saddr or dport.
 * @return A JSON payload expression.
 */
nlohmann::json payload(const std::string &protocol, const char *field) {
	nlohmann::json selector;
	selector["protocol"] = protocol;
	selector["field"]	 = field;
	return nlohmann::json{
		{"payload", std::move(selector)}
	};
}

/**
 * @brief Builds a meta selector expression, such as meta l4proto.
 * @param key Meta key.
 * @return A JSON meta expression.
 */
nlohmann::json meta(const char *key) {
	return nlohmann::json{
		{"meta", nlohmann::json{{"key", key}}}
	};
}

/**
 * @brief Builds an address match using the correct nftables IP protocol.
 * @param value Validated address or subnet.
 * @param direction nftables direction field, such as saddr or daddr.
 * @return A JSON match statement for the address.
 */
nlohmann::json addressMatch(const std::string &value, const char *direction) {
	const ParsedAddress parsed = parseAddress(value);
	nlohmann::json		right  = parsed.address;
	if (parsed.prefix_length) {
		right = nlohmann::json{
			{"prefix",
			 nlohmann::json{{"addr", parsed.address},
							{"len", *parsed.prefix_length}}}
		   };
	}
	return match("==", payload(parsed.ipv4 ? "ip" : "ip6", direction),
				 std::move(right));
}

/**
 * @brief Validates that the addresses and protocol can match the same packet.
 * @param rule Rule whose individual fields are otherwise valid.
 * @return No value.
 * @throws InvalidRuleError If an address is invalid or the fields conflict.
 */
void validateIpVersions(const RuleSpec &rule) {
	std::optional<bool> ipv4;
	for (const auto *value : {&rule.source_address, &rule.destination_address}) {
		if (!*value) {
			continue;
		}
		const bool addressIpv4 = parseAddress(**value).ipv4;
		if (ipv4 && *ipv4 != addressIpv4) {
			throw InvalidRuleError(
				"Source and destination addresses must use the same IP version");
		}
		ipv4 = addressIpv4;
	}
	if (ipv4 && ((rule.family == "ip" && !*ipv4) ||
				 (rule.family == "ip6" && *ipv4))) {
		throw InvalidRuleError("An address is invalid for the selected family");
	}
	const bool icmp	  = rule.protocol == "icmp";
	const bool icmpv6 = rule.protocol == "icmpv6";
	if ((icmp && (rule.family == "ip6" || ipv4 == false)) ||
		(icmpv6 && (rule.family == "ip" || ipv4 == true))) {
		throw InvalidRuleError(
			"The protocol is invalid for the selected family or addresses");
	}
}

} // namespace

bool isIdentifier(const std::string &value) {
	const auto isAlpha = [](unsigned char character) {
		return (character >= 'a' && character <= 'z') ||
			   (character >= 'A' && character <= 'Z');
	};
	const auto isDigit = [](unsigned char character) {
		return character >= '0' && character <= '9';
	};

	if (value.empty() ||
		value.size() > Config::Limits::MAX_FIREWALL_IDENTIFIER_LENGTH ||
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

void validateRule(const RuleSpec &rule) {
	if (rule.family != "ip" && rule.family != "ip6" && rule.family != "inet") {
		throw InvalidRuleError("family must be ip, ip6, or inet");
	}
	if (!isIdentifier(rule.table) || !isIdentifier(rule.chain)) {
		throw InvalidRuleError(
			"table and chain must be valid nftables identifiers");
	}
	if (rule.protocol && *rule.protocol != "tcp" && *rule.protocol != "udp" &&
		*rule.protocol != "icmp" && *rule.protocol != "icmpv6") {
		throw InvalidRuleError("protocol must be tcp, udp, icmp, or icmpv6");
	}
	if (rule.action != "accept" && rule.action != "drop" &&
		rule.action != "reject") {
		throw InvalidRuleError("action must be accept, drop, or reject");
	}
	if (!rule.protocol && !rule.source_address && !rule.destination_address &&
		!rule.destination_port && !rule.input_interface &&
		!rule.output_interface && rule.connection_states.empty()) {
		throw InvalidRuleError("at least one match is required");
	}
	if (rule.destination_port_end && !rule.destination_port) {
		throw InvalidRuleError(
			"destination_port_end requires destination_port");
	}
	if (rule.destination_port_end &&
		*rule.destination_port_end < *rule.destination_port) {
		throw InvalidRuleError(
			"destination_port_end must not be below destination_port");
	}
	if (rule.destination_port && rule.protocol != "tcp" &&
		rule.protocol != "udp") {
		throw InvalidRuleError("A destination port requires tcp or udp");
	}
	for (const auto *name : {&rule.input_interface, &rule.output_interface}) {
		if (*name && !isInterfaceName(**name)) {
			throw InvalidRuleError("An interface name is invalid");
		}
	}
	for (const std::string &state : rule.connection_states) {
		if (std::find(CONNECTION_STATES.begin(), CONNECTION_STATES.end(),
					  state) == CONNECTION_STATES.end()) {
			throw InvalidRuleError("connection_states must contain only new, "
								   "established, related, or invalid");
		}
	}
	validateIpVersions(rule);
}

nlohmann::json ruleExpressions(const RuleSpec &rule) {
	nlohmann::json expressions = nlohmann::json::array();
	if (rule.input_interface) {
		expressions.push_back(
			match("==", meta("iifname"), *rule.input_interface));
	}
	if (rule.output_interface) {
		expressions.push_back(
			match("==", meta("oifname"), *rule.output_interface));
	}
	if (!rule.connection_states.empty()) {
		nlohmann::json states = nlohmann::json::array();
		for (const char *state : CONNECTION_STATES) {
			if (std::find(rule.connection_states.begin(),
						  rule.connection_states.end(),
						  state) != rule.connection_states.end()) {
				states.push_back(state);
			}
		}
		expressions.push_back(match("in",
									nlohmann::json{
										{"ct", nlohmann::json{{"key", "state"}}}
		},
									std::move(states)));
	}
	if (rule.source_address) {
		expressions.push_back(addressMatch(*rule.source_address, "saddr"));
	}
	if (rule.destination_address) {
		expressions.push_back(addressMatch(*rule.destination_address, "daddr"));
	}
	if (rule.protocol) {
		// nftables names ICMPv6 ipv6-icmp in layer-4 protocol matches.
		expressions.push_back(
			match("==", meta("l4proto"),
				  *rule.protocol == "icmpv6" ? "ipv6-icmp" : *rule.protocol));
	}
	if (rule.destination_port) {
		nlohmann::json port = *rule.destination_port;
		if (rule.destination_port_end &&
			*rule.destination_port_end != *rule.destination_port) {
			port = nlohmann::json{
				{"range", nlohmann::json::array({*rule.destination_port,
												 *rule.destination_port_end})}
			   };
		}
		expressions.push_back(match("==", payload(*rule.protocol, "dport"),
									std::move(port)));
	}
	expressions.push_back(nlohmann::json{
		{rule.action, nullptr}
	  });
	return expressions;
}

} // namespace Firewall::Detail
