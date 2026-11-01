#include "network/address.hpp"

#include <arpa/inet.h>

namespace Network {

bool isLoopbackAddress(const std::string &address) {
	if (address == "localhost") {
		return true;
	}
	in_addr ipv4{};
	if (inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
		return (ntohl(ipv4.s_addr) >> 24) == 127;
	}
	in6_addr ipv6{};
	if (inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
		if (IN6_IS_ADDR_LOOPBACK(&ipv6)) {
			return true;
		}
		if (IN6_IS_ADDR_V4MAPPED(&ipv6) && ipv6.s6_addr[12] == 127) {
			return true;
		}
	}
	return false;
}

} // namespace Network
