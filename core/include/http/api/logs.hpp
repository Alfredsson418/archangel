#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../firewall/firewall.hpp"

namespace HttpApi {
/**
 * @brief Returns a bounded set of supported application and firewall logs.
 * @param firewall Backend used to determine whether nftables logging is active.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes the log-source collection as JSON.
 */
void getLogs(Firewall &firewall, const httplib::Request &request,
			 httplib::Response &response);
} // namespace HttpApi
