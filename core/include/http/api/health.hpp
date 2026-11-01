#pragma once

#include "cpp-httplib/cpp-httplib.hpp"

namespace Http {

/**
 * @brief Writes an empty HTTP 200 response when the service is online.
 * @param request Incoming HTTP request (unused by the health response).
 * @param response HTTP response to populate.
 * @return No value; sets only the HTTP status code.
 */
void getHealth(const httplib::Request &request, httplib::Response &response);

} // namespace Http
