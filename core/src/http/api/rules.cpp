#include "../../../include/http/api/rules.hpp"
#include "api_common.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace {
using HttpApi::Detail::Json;

Json parseObject(const httplib::Request &request) {
	try {
		Json body = Json::parse(request.body);
		if (!body.is_object()) {
			throw ValidationError("Request body must be a JSON object");
		}
		return body;
	} catch (const Json::parse_error &) {
		throw ValidationError("Request body must contain valid JSON");
	}
}

std::string requiredString(const Json &body, const char *field) {
	const auto value = body.find(field);
	if (value == body.end() || !value->is_string() ||
		value->get<std::string>().empty()) {
		throw ValidationError(std::string(field) +
							  " is required and must be a string");
	}
	return value->get<std::string>();
}

std::optional<std::string> optionalString(const Json &body, const char *field) {
	const auto value = body.find(field);
	if (value == body.end() || value->is_null()) {
		return std::nullopt;
	}
	if (!value->is_string()) {
		throw ValidationError(std::string(field) + " must be a string");
	}
	return value->get<std::string>();
}

RuleSpec parseRule(const Json &body) {
	RuleSpec rule;
	rule.family				 = requiredString(body, "family");
	rule.table				 = requiredString(body, "table");
	rule.chain				 = requiredString(body, "chain");
	rule.protocol			 = requiredString(body, "protocol");
	rule.action				 = requiredString(body, "action");
	rule.source_address		 = optionalString(body, "source_address");
	rule.destination_address = optionalString(body, "destination_address");

	const auto port = body.find("destination_port");
	if (port != body.end() && !port->is_null()) {
		std::uint64_t value = 0;
		if (port->is_number_unsigned()) {
			value = port->get<std::uint64_t>();
		} else if (port->is_number_integer()) {
			const auto signedValue = port->get<std::int64_t>();
			if (signedValue < 0) {
				throw ValidationError(
					"destination_port must be between 1 and 65535");
			}
			value = static_cast<std::uint64_t>(signedValue);
		} else {
			throw ValidationError("destination_port must be an integer");
		}
		if (value == 0 || value > 65535) {
			throw ValidationError(
				"destination_port must be between 1 and 65535");
		}
		rule.destination_port = static_cast<std::uint16_t>(value);
	}
	return rule;
}

std::uint64_t parseHandle(const Json &body) {
	const auto handle = body.find("handle");
	if (handle == body.end() || !handle->is_number_integer()) {
		throw ValidationError(
			"handle is required and must be a positive integer");
	}
	if (handle->is_number_unsigned()) {
		const auto value = handle->get<std::uint64_t>();
		if (value > 0)
			return value;
	} else {
		const auto value = handle->get<std::int64_t>();
		if (value > 0)
			return static_cast<std::uint64_t>(value);
	}
	throw ValidationError("handle is required and must be a positive integer");
}
} // namespace

namespace HttpApi {

void getRules(Firewall			&firewall, const httplib::Request &,
			  httplib::Response &response) {
	Logger::API::log("GET /api/v1/rules");
	try {
		response.set_content(firewall.listRules(), "application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "GET /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

void createRule(Firewall &firewall, const httplib::Request &request,
				httplib::Response &response) {
	try {
		firewall.addRule(parseRule(parseObject(request)));
		Logger::API::log("POST /api/v1/rules succeeded");
		response.status = 201;
		response.set_content(
			Json{
				{"status", "created"}
		 }
				.dump(),
			"application/json");
	} catch (const ApiError &error) {
		Detail::sendError(response, error);
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "POST /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

void deleteRule(Firewall &firewall, const httplib::Request &request,
				httplib::Response &response) {
	try {
		const Json body = parseObject(request);
		firewall.deleteRule(requiredString(body, "family"),
							requiredString(body, "table"),
							requiredString(body, "chain"), parseHandle(body));
		Logger::API::log("DELETE /api/v1/rules succeeded");
		response.set_content(
			Json{
				{"status", "deleted"}
		 }
				.dump(),
			"application/json");
	} catch (const ApiError &error) {
		Detail::sendError(response, error);
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "DELETE /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

} // namespace HttpApi
