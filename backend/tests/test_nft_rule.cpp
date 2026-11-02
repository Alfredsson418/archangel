#include "../src/firewall/providers/nft_rule.hpp"
#include "test_support.hpp"

#include <functional>
#include <string>
#include <vector>

namespace {
using nlohmann::json;

Firewall::RuleSpec baseRule() {
	Firewall::RuleSpec rule;
	rule.family = "inet";
	rule.table	= "filter";
	rule.chain	= "input";
	rule.action = "accept";
	return rule;
}

void requireInvalid(const std::function<void(Firewall::RuleSpec &)> &change,
					const std::string								&message) {
	Firewall::RuleSpec rule = baseRule();
	rule.protocol			= "tcp";
	change(rule);
	TestSupport::requireThrows<Firewall::InvalidRuleError>(
		[&] { Firewall::Detail::validateRule(rule); }, message);
}

void rejectsInvalidRules() {
	requireInvalid([](auto &rule) { rule.family = "bridge"; },
				   "unsupported family");
	requireInvalid([](auto &rule) { rule.table = "bad name"; },
				   "invalid table name");
	requireInvalid([](auto &rule) { rule.protocol = "sctp"; },
				   "unsupported protocol");
	requireInvalid([](auto &rule) { rule.action = "queue"; },
				   "unsupported action");
	requireInvalid([](auto &rule) { rule.protocol.reset(); },
				   "rule with no match");
	requireInvalid([](auto &rule) { rule.source_address = "nonsense"; },
				   "invalid address");
	requireInvalid(
		[](auto &rule) {
			rule.protocol.reset();
			rule.destination_port = 22;
		},
		"port with no protocol");
	requireInvalid(
		[](auto &rule) {
			rule.protocol		  = "icmp";
			rule.destination_port = 22;
		},
		"port with ICMP");
	requireInvalid([](auto &rule) { rule.destination_port_end = 22; },
				   "range end with no start");
	requireInvalid(
		[](auto &rule) {
			rule.destination_port	  = 100;
			rule.destination_port_end = 99;
		},
		"reversed port range");
	requireInvalid([](auto &rule) { rule.input_interface = "has space"; },
				   "invalid interface name");
	requireInvalid([](auto &rule) { rule.output_interface = "a/b"; },
				   "interface name with a slash");
	requireInvalid(
		[](auto &rule) { rule.input_interface = "sixteen-letters-"; },
		"over-long interface name");
	requireInvalid([](auto &rule) { rule.connection_states = {"untracked"}; },
				   "unsupported connection state");
}

void rejectsSubnetsThatWouldBeSilentlyChanged() {
	for (const std::string address :
		 {"192.168.1.5/24", "10.0.0.1/8", "2001:db8::1/32", "0.0.0.1/0",
		  "192.168.1.0/33", "192.168.1.0/-1", "192.168.1.0/", "192.168.1.0/x",
		  "192.168.1.0/24/24", "2001:db8::/129"}) {
		requireInvalid([&](auto &rule) { rule.source_address = address; },
					   "invalid subnet " + address);
	}
}

void rejectsFieldsThatCouldNeverMatchTogether() {
	requireInvalid(
		[](auto &rule) {
			rule.family			= "ip";
			rule.source_address = "2001:db8::1";
		},
		"IPv6 address in the ip family");
	requireInvalid(
		[](auto &rule) {
			rule.family			= "ip6";
			rule.source_address = "192.0.2.0/24";
		},
		"IPv4 subnet in the ip6 family");
	requireInvalid(
		[](auto &rule) {
			rule.source_address		 = "192.0.2.1";
			rule.destination_address = "2001:db8::1";
		},
		"mixed IP versions");
	requireInvalid(
		[](auto &rule) {
			rule.family	  = "ip";
			rule.protocol = "icmpv6";
		},
		"ICMPv6 in the ip family");
	requireInvalid(
		[](auto &rule) {
			rule.family	  = "ip6";
			rule.protocol = "icmp";
		},
		"ICMP in the ip6 family");
	requireInvalid(
		[](auto &rule) {
			rule.protocol		= "icmpv6";
			rule.source_address = "192.0.2.1";
		},
		"ICMPv6 with an IPv4 address");
	requireInvalid(
		[](auto &rule) {
			rule.protocol		= "icmp";
			rule.source_address = "2001:db8::1";
		},
		"ICMP with an IPv6 address");
}

void acceptsValidRules() {
	const std::vector<std::function<void(Firewall::RuleSpec &)>> rules = {
		[](auto &rule) { rule.protocol = "tcp"; },
		[](auto &rule) { rule.protocol = "icmp"; },
		[](auto &rule) { rule.protocol = "icmpv6"; },
		[](auto &rule) { rule.source_address = "0.0.0.0/0"; },
		[](auto &rule) { rule.destination_address = "2001:db8::/32"; },
		[](auto &rule) { rule.input_interface = "lo"; },
		[](auto &rule) { rule.output_interface = "wg0.100_x-1"; },
		[](auto &rule) { rule.connection_states = {"related", "new"}; },
	};
	for (const auto &change : rules) {
		Firewall::RuleSpec rule = baseRule();
		change(rule);
		Firewall::Detail::validateRule(rule);
	}
}

void buildsExactlyTheStatementsNftablesExpects() {
	Firewall::RuleSpec rule	  = baseRule();
	rule.action				  = "drop";
	rule.input_interface	  = "eth0";
	rule.output_interface	  = "lo";
	rule.connection_states	  = {"related", "new"};
	rule.source_address		  = "192.168.1.0/24";
	rule.destination_address  = "192.0.2.1/32";
	rule.protocol			  = "tcp";
	rule.destination_port	  = 8000;
	rule.destination_port_end = 8100;

	const json expected = json::parse(R"([
		{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
		{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},
		{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["new","related"]}},
		{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.168.1.0","len":24}}}},
		{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}},
		{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"range":[8000,8100]}}},
		{"drop":null}
	])");
	TestSupport::require(Firewall::Detail::ruleExpressions(rule) == expected,
						 "full rule should build the expected statements");
}

void normalizesValuesThatNftablesReadsBackSimplified() {
	Firewall::RuleSpec rule	  = baseRule();
	rule.protocol			  = "udp";
	rule.destination_port	  = 80;
	rule.destination_port_end = 80;
	rule.source_address		  = "2001:db8::1/128";
	const json statements	  = Firewall::Detail::ruleExpressions(rule);
	TestSupport::require(statements[0]["match"]["right"] == "2001:db8::1",
						 "a host-length subnet should become a plain address");
	TestSupport::require(statements[2]["match"]["right"] == 80,
						 "a one-port range should become a plain port");

	rule		  = baseRule();
	rule.protocol = "icmpv6";
	TestSupport::require(Firewall::Detail::ruleExpressions(
							 rule)[0]["match"]["right"] == "ipv6-icmp",
						 "ICMPv6 should use the nftables protocol name");
}
} // namespace

void runNftRuleTests() {
	rejectsInvalidRules();
	rejectsSubnetsThatWouldBeSilentlyChanged();
	rejectsFieldsThatCouldNeverMatchTogether();
	acceptsValidRules();
	buildsExactlyTheStatementsNftablesExpects();
	normalizesValuesThatNftablesReadsBackSimplified();
}
