#pragma once

#include "../../../include/error.hpp"
#include "../../../include/logger.hpp"
#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../../lib/json/json.hpp"
#include <exception>
#include <string>

namespace HttpApi::Detail {
using Json = nlohmann::json;

/**
 * @brief Serializes an API error into the standard JSON response format.
 * @param response HTTP response to populate.
 * @param error Error containing the HTTP status, code, and client message.
 * @return No value; writes the error response and logs its category.
 */
inline void sendError(httplib::Response &response, const ApiError &error) {
	Logger::API::log("request_rejected code=" + error.code(),
					 Logger::Level::WARNING);
	response.status = error.status();
	response.set_content(
		Json{
			{"error", error.what()},
			{ "code", error.code()}
	  }
			.dump(),
		"application/json");
}

/**
 * @brief Sends an internal operation failure without exposing details.
 * @param response HTTP response to populate.
 * @param operation Safe operation identifier for diagnostics.
 * @param error Exception associated with the failure.
 * @param code Stable machine-readable error code.
 * @param message Safe client-facing error message.
 * @return No value; writes an HTTP 500 JSON response.
 */
inline void sendOperationError(httplib::Response &response,
							   const char *operation, const std::exception &,
							   const char *code	   = "operation_error",
							   const char *message = "Operation failed") {
	Logger::API::log(std::string("operation_failed operation=") + operation +
						 " error_code=" + code,
					 Logger::Level::ERROR);
	response.status = 500;
	response.set_content(
		Json{
			{"error", message},
			   { "code",	code}
	 }
			.dump(),
		"application/json");
}
} // namespace HttpApi::Detail
