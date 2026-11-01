#pragma once

#include "cpp-httplib/cpp-httplib.hpp"
#include "firewall/firewall.hpp"

namespace Http {

/**
 * @brief Writes backend firewall statistics as a JSON HTTP response.
 * @param firewall Backend providing active ruleset statistics.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes statistics or an error to response.
 */
void getStatistics(Firewall::Backend &firewall, const httplib::Request &request,
				   httplib::Response &response);

} // namespace Http
