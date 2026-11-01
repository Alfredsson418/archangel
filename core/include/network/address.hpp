#pragma once

#include <string>

namespace Network {

/**
 * @brief Determines whether an IPv4 or IPv6 address is loopback.
 * @param address Numeric address or the hostname "localhost".
 * @return True for loopback addresses; false for other or invalid values.
 */
bool isLoopbackAddress(const std::string &address);

} // namespace Network
