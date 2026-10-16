#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../firewall/firewall.hpp"

namespace HttpApi {
/**
 * @brief Writes backend firewall statistics as a JSON HTTP response.
 * @param firewall Backend providing active ruleset statistics.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes statistics or an error to response.
 */
void getStatistics(Firewall &firewall, const httplib::Request &request,
				   httplib::Response &response);
} // namespace HttpApi
