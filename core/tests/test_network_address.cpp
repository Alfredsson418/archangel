#include "network/address.hpp"
#include "test_support.hpp"

namespace {
void identifiesLoopbackAddresses() {
	TestSupport::require(Network::isLoopbackAddress("localhost"),
						 "localhost should be treated as loopback");
	TestSupport::require(Network::isLoopbackAddress("127.0.0.1"),
						 "IPv4 loopback should be recognized");
	TestSupport::require(Network::isLoopbackAddress("127.255.1.2"),
						 "the full IPv4 loopback range should be recognized");
	TestSupport::require(Network::isLoopbackAddress("::1"),
						 "IPv6 loopback should be recognized");
	TestSupport::require(Network::isLoopbackAddress("::ffff:127.0.0.1"),
						 "IPv4-mapped loopback should be recognized");
}

void rejectsNonLoopbackAndInvalidAddresses() {
	TestSupport::require(!Network::isLoopbackAddress("192.168.1.1"),
						 "private IPv4 addresses are not loopback");
	TestSupport::require(!Network::isLoopbackAddress("2001:db8::1"),
						 "non-loopback IPv6 addresses are not loopback");
	TestSupport::require(!Network::isLoopbackAddress("not-an-address"),
						 "invalid addresses are not loopback");
}
} // namespace

void runNetworkAddressTests() {
	identifiesLoopbackAddresses();
	rejectsNonLoopbackAndInvalidAddresses();
}
