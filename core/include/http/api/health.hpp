#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {
/**
 * @brief Writes the plain-text service health response.
 * @param request Incoming HTTP request (unused by the health response).
 * @param response HTTP response to populate.
 * @return No value; writes the result to response.
 */
void getHealth(const httplib::Request &request, httplib::Response &response);
} // namespace HttpApi
