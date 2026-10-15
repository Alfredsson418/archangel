#pragma once

#include "../../../include/error.hpp"
#include "../../../include/logger.hpp"
#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../../lib/json/json.hpp"
#include <exception>
#include <string>

namespace HttpApi::Detail {
using Json = nlohmann::json;

inline void sendError(httplib::Response &response, const ApiError &error) {
	Logger::API::log("Request rejected (" + error.code() + "): " + error.what(),
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

inline void sendOperationError(httplib::Response	&response,
							   const char			*operation,
							   const std::exception &error,
							   const char			*code = "operation_error",
							   const char *message = "Operation failed") {
	Logger::API::log(std::string(operation) + " failed: " + error.what(),
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
