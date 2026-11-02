#include "http/api/rules.hpp"
#include "api_common.hpp"
#include "config/app_config.hpp"
#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Http {

namespace {
using Detail::Json;

/**
 * @brief Parses the request body and requires a JSON object at its root.
 * @param request HTTP request containing the JSON body.
 * @return The parsed JSON object.
 * @throws ValidationError If the body is invalid JSON or not an object.
 */
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

/**
 * @brief Reads a required non-empty string property.
 * @param body JSON object containing the property.
 * @param field Name of the required property.
 * @return The property's string value.
 * @throws ValidationError If the property is absent, empty, or not a string.
 */
std::string requiredString(const Json &body, const char *field) {
	const auto value = body.find(field);
	if (value == body.end() || !value->is_string() ||
		value->get<std::string>().empty()) {
		throw ValidationError(std::string(field) +
							  " is required and must be a string");
	}
	return value->get<std::string>();
}

/**
 * @brief Reads an optional string property.
 * @param body JSON object containing the property.
 * @param field Name of the optional property.
 * @return The property's value, or std::nullopt if absent or null.
 * @throws ValidationError If a non-null property is not a string.
 */
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

/**
 * @brief Rejects properties the API does not recognize.
 *
 * Without this, a backend that predates a field would ignore it and could
 * create a broader rule than the caller asked for.
 *
 * @param body JSON request object.
 * @param allowed Every property the operation accepts.
 * @return No value.
 * @throws ValidationError If the body has any other property.
 */
void rejectUnknownFields(const Json &body,
						 std::initializer_list<std::string_view> allowed) {
	for (const auto &item : body.items()) {
		if (std::find(allowed.begin(), allowed.end(), item.key()) ==
			allowed.end()) {
			throw ValidationError("Request contains an unsupported field");
		}
	}
}

/**
 * @brief Reads an optional port property.
 * @param body JSON object containing the property.
 * @param field Name of the optional property.
 * @return The port, or std::nullopt if absent or null.
 * @throws ValidationError If the value is not an integer from 1 to 65535.
 */
std::optional<std::uint16_t> optionalPort(const Json &body, const char *field) {
	const auto port = body.find(field);
	if (port == body.end() || port->is_null()) {
		return std::nullopt;
	}
	if (!port->is_number_integer()) {
		throw ValidationError(std::string(field) + " must be an integer");
	}
	if (port->is_number_unsigned() ? port->get<std::uint64_t>() == 0 ||
										 port->get<std::uint64_t>() > 65535
								   : port->get<std::int64_t>() < 1 ||
										 port->get<std::int64_t>() > 65535) {
		throw ValidationError(std::string(field) +
							  " must be between 1 and 65535");
	}
	return static_cast<std::uint16_t>(port->get<std::uint64_t>());
}

/**
 * @brief Reads the optional list of connection states.
 * @param body JSON object containing the property.
 * @return The listed states, or an empty list if absent or null.
 * @throws ValidationError If the value is not a bounded list of strings.
 */
std::vector<std::string> connectionStates(const Json &body) {
	const auto states = body.find("connection_states");
	if (states == body.end() || states->is_null()) {
		return {};
	}
	if (!states->is_array() ||
		states->size() > Config::Limits::MAX_CONNECTION_STATES) {
		throw ValidationError("connection_states must be a list of up to " +
							  std::to_string(
								  Config::Limits::MAX_CONNECTION_STATES) +
							  " states");
	}
	std::vector<std::string> result;
	for (const Json &state : *states) {
		if (!state.is_string()) {
			throw ValidationError("connection_states must contain strings");
		}
		result.push_back(state.get<std::string>());
	}
	return result;
}

/**
 * @brief Converts and validates rule fields into the backend-neutral model.
 * @param body JSON request object.
 * @return Structured rule ready to pass to the firewall backend.
 * @throws ValidationError If a field is unknown, or a required field or port
 * is invalid.
 */
Firewall::RuleSpec parseRule(const Json &body) {
	rejectUnknownFields(body, {"family", "table", "chain", "protocol",
							   "source_address", "destination_address",
							   "destination_port", "destination_port_end",
							   "input_interface", "output_interface",
							   "connection_states", "action"});
	Firewall::RuleSpec rule;
	rule.family				  = requiredString(body, "family");
	rule.table				  = requiredString(body, "table");
	rule.chain				  = requiredString(body, "chain");
	rule.protocol			  = optionalString(body, "protocol");
	rule.action				  = requiredString(body, "action");
	rule.source_address		  = optionalString(body, "source_address");
	rule.destination_address  = optionalString(body, "destination_address");
	rule.destination_port	  = optionalPort(body, "destination_port");
	rule.destination_port_end = optionalPort(body, "destination_port_end");
	rule.input_interface	  = optionalString(body, "input_interface");
	rule.output_interface	  = optionalString(body, "output_interface");
	rule.connection_states	  = connectionStates(body);
	return rule;
}

/**
 * @brief Reads and validates a positive integer rule handle.
 * @param body JSON object containing the handle property.
 * @return The handle represented as an unsigned integer.
 * @throws ValidationError If the handle is absent, invalid, or not positive.
 */
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

void getRules(Firewall::Backend &firewall, const httplib::Request &,
			  httplib::Response &response) {
	try {
		response.set_content(firewall.listRules(), "application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "GET /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

void createRule(Firewall::Backend &firewall, const httplib::Request &request,
				httplib::Response &response) {
	try {
		firewall.addRule(parseRule(parseObject(request)));
		response.status = 201;
		response.set_content(
			Json{
				{"status", "created"}
		 }
				.dump(),
			"application/json");
	} catch (const ApiError &error) {
		Detail::sendError(response, error);
	} catch (const Firewall::InvalidRuleError &error) {
		Detail::sendError(response, ValidationError(error.what()));
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "POST /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

void deleteRule(Firewall::Backend &firewall, const httplib::Request &request,
				httplib::Response &response) {
	try {
		const Json body = parseObject(request);
		rejectUnknownFields(body, {"family", "table", "chain", "handle"});
		firewall.deleteRule(requiredString(body, "family"),
							requiredString(body, "table"),
							requiredString(body, "chain"), parseHandle(body));
		response.set_content(
			Json{
				{"status", "deleted"}
		 }
				.dump(),
			"application/json");
	} catch (const ApiError &error) {
		Detail::sendError(response, error);
	} catch (const Firewall::InvalidRuleError &error) {
		Detail::sendError(response, ValidationError(error.what()));
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "DELETE /api/v1/rules", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

} // namespace Http
