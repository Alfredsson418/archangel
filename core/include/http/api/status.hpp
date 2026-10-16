#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include <cstdint>
#include <string>

namespace HttpApi {
/**
 * @brief Writes backend version, API schema, and process uptime as JSON.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @param backendVersion Git commit hash embedded in the backend binary.
 * @param uptimeSeconds Number of seconds the backend process has been running.
 * @return No value; writes the JSON status response.
 */
void getStatus(const httplib::Request &request, httplib::Response &response,
			   const std::string &backendVersion, std::uint64_t uptimeSeconds);
} // namespace HttpApi
