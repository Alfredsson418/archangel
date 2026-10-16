#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {
/**
 * @brief Collects host resource information and writes it as JSON.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes system statistics or an error to response.
 */
void getSystemStatistics(const httplib::Request &request,
						 httplib::Response		&response);
} // namespace HttpApi
