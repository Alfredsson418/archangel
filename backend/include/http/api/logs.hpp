#pragma once

#include "cpp-httplib/cpp-httplib.hpp"
#include "logs/log_source.hpp"

#include <memory>
#include <vector>

namespace Http {

/**
 * @brief Returns recent entries from each configured log source.
 * @param sources Log sources in display order, built at startup.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes the bounded, redacted log-source collection as
 * JSON.
 */
void getLogs(const std::vector<std::unique_ptr<Logs::LogSource>> &sources,
			 const httplib::Request &request, httplib::Response &response);

} // namespace Http
