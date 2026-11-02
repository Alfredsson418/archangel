#include "http/api/rules.hpp"
#include "api_common.hpp"
#include "config/app_config.hpp"
#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
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
void rejectUnknownFields(const Json								&body,
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
		throw ValidationError(
			"connection_states must be a list of up to " +
			std::to_string(Config::Limits::MAX_CONNECTION_STATES) + " states");
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
/**
 * @brief Reads the required rule object of a change.
 * @param entry JSON object describing the change.
 * @return The parsed rule.
 * @throws ValidationError If the rule is absent or invalid.
 */
Firewall::RuleSpec changeRule(const Json &entry) {
	const auto rule = entry.find("rule");
	if (rule == entry.end() || !rule->is_object()) {
		throw ValidationError("rule is required and must be an object");
	}
	return parseRule(*rule);
}

/**
 * @brief Reads a rule order of handles and IDs of rules added in the same list.
 * @param entry JSON object describing the change.
 * @return The order.
 * @throws ValidationError If the order is absent or has an invalid entry.
 */
std::vector<std::variant<std::uint64_t, std::string>>
changeOrder(const Json &entry) {
	const auto order = entry.find("order");
	if (order == entry.end() || !order->is_array()) {
		throw ValidationError("order is required and must be a list");
	}
	std::vector<std::variant<std::uint64_t, std::string>> result;
	for (const Json &item : *order) {
		if (item.is_string()) {
			result.emplace_back(item.get<std::string>());
		} else if (item.is_number_unsigned() && item.get<std::uint64_t>() > 0) {
			result.emplace_back(item.get<std::uint64_t>());
		} else {
			throw ValidationError(
				"order must contain positive handles or change IDs");
		}
	}
	return result;
}

/**
 * @brief Reads the optional base-chain definition of a new chain.
 * @param entry JSON object describing the change.
 * @return The definition, or std::nullopt for a regular chain.
 * @throws ValidationError If the definition is malformed.
 */
std::optional<Firewall::BaseChain> changeBaseChain(const Json &entry) {
	const auto base = entry.find("base");
	if (base == entry.end() || base->is_null()) {
		return std::nullopt;
	}
	if (!base->is_object()) {
		throw ValidationError("base must be an object");
	}
	rejectUnknownFields(*base, {"type", "hook", "priority", "policy"});
	const auto priority = base->find("priority");
	if (priority == base->end() || !priority->is_number_integer() ||
		priority->get<std::int64_t>() < -Config::Limits::MAX_CHAIN_PRIORITY ||
		priority->get<std::int64_t>() > Config::Limits::MAX_CHAIN_PRIORITY) {
		throw ValidationError(
			"priority must be an integer between -" +
			std::to_string(Config::Limits::MAX_CHAIN_PRIORITY) + " and " +
			std::to_string(Config::Limits::MAX_CHAIN_PRIORITY));
	}
	return Firewall::BaseChain{
		requiredString(*base, "type"), requiredString(*base, "hook"),
		static_cast<std::int32_t>(priority->get<std::int64_t>()),
		requiredString(*base, "policy")};
}

/**
 * @brief Parses one entry of a change list.
 * @param entry JSON object describing the change.
 * @return The structured change.
 * @throws ValidationError If the entry is malformed or has an unknown type.
 */
Firewall::Change parseChange(const Json &entry) {
	if (!entry.is_object()) {
		throw ValidationError("Each change must be a JSON object");
	}
	const std::string type = requiredString(entry, "type");
	if (type == "add_rule") {
		rejectUnknownFields(entry, {"type", "rule", "id"});
		const std::string id = optionalString(entry, "id").value_or("");
		if (id.size() > Config::Limits::MAX_CHANGE_ID_LENGTH) {
			throw ValidationError("id is too long");
		}
		return Firewall::AddRuleChange{changeRule(entry), id};
	}
	if (type == "replace_rule") {
		rejectUnknownFields(entry, {"type", "handle", "rule"});
		return Firewall::ReplaceRuleChange{changeRule(entry),
										   parseHandle(entry)};
	}
	if (type == "delete_rule") {
		rejectUnknownFields(entry,
							{"type", "family", "table", "chain", "handle"});
		return Firewall::DeleteRuleChange{
			requiredString(entry, "family"), requiredString(entry, "table"),
			requiredString(entry, "chain"), parseHandle(entry)};
	}
	if (type == "set_rule_order") {
		rejectUnknownFields(entry,
							{"type", "family", "table", "chain", "order"});
		return Firewall::SetRuleOrderChange{
			requiredString(entry, "family"), requiredString(entry, "table"),
			requiredString(entry, "chain"), changeOrder(entry)};
	}
	if (type == "create_chain") {
		rejectUnknownFields(entry, {"type", "family", "table", "name", "base"});
		return Firewall::CreateChainChange{
			requiredString(entry, "family"), requiredString(entry, "table"),
			requiredString(entry, "name"), changeBaseChain(entry)};
	}
	if (type == "rename_chain") {
		rejectUnknownFields(entry,
							{"type", "family", "table", "name", "new_name"});
		return Firewall::RenameChainChange{
			requiredString(entry, "family"), requiredString(entry, "table"),
			requiredString(entry, "name"), requiredString(entry, "new_name")};
	}
	if (type == "set_chain_policy") {
		rejectUnknownFields(entry,
							{"type", "family", "table", "name", "policy"});
		return Firewall::SetChainPolicyChange{
			requiredString(entry, "family"), requiredString(entry, "table"),
			requiredString(entry, "name"), requiredString(entry, "policy")};
	}
	if (type == "delete_chain") {
		rejectUnknownFields(entry, {"type", "family", "table", "name"});
		return Firewall::DeleteChainChange{requiredString(entry, "family"),
										   requiredString(entry, "table"),
										   requiredString(entry, "name")};
	}
	if (type == "create_table" || type == "delete_table") {
		rejectUnknownFields(entry, {"type", "family", "name"});
		if (type == "create_table") {
			return Firewall::CreateTableChange{requiredString(entry, "family"),
											   requiredString(entry, "name")};
		}
		return Firewall::DeleteTableChange{requiredString(entry, "family"),
										   requiredString(entry, "name")};
	}
	if (type == "set_table_enabled") {
		rejectUnknownFields(entry, {"type", "family", "name", "enabled"});
		const auto enabled = entry.find("enabled");
		if (enabled == entry.end() || !enabled->is_boolean()) {
			throw ValidationError(
				"enabled is required and must be true or false");
		}
		return Firewall::SetTableEnabledChange{requiredString(entry, "family"),
											   requiredString(entry, "name"),
											   enabled->get<bool>()};
	}
	throw ValidationError("Change type is not supported");
}

/**
 * @brief Parses a bounded change list and its expected chain revisions.
 * @param request Request carrying the change list as JSON.
 * @return The structured change set.
 * @throws ValidationError If the request is malformed or too large.
 */
Firewall::ChangeSet parseChangeSet(const httplib::Request &request) {
	if (request.body.size() > Config::Limits::MAX_FIREWALL_CHANGES_BYTES) {
		throw ValidationError("Request body is too large");
	}
	const Json body = parseObject(request);
	rejectUnknownFields(body, {"expected_revisions", "changes"});
	const auto changes	= body.find("changes");
	const auto expected = body.find("expected_revisions");
	if (changes == body.end() || !changes->is_array() || changes->empty() ||
		changes->size() > Config::Limits::MAX_FIREWALL_CHANGES) {
		throw ValidationError(
			"changes must be a list of 1 to " +
			std::to_string(Config::Limits::MAX_FIREWALL_CHANGES) + " changes");
	}
	if (expected == body.end() || !expected->is_array() ||
		expected->size() > Config::Limits::MAX_FIREWALL_CHANGES) {
		throw ValidationError("expected_revisions must be a list");
	}

	Firewall::ChangeSet result;
	for (const Json &entry : *expected) {
		if (!entry.is_object()) {
			throw ValidationError("Each expected revision must be an object");
		}
		rejectUnknownFields(entry, {"family", "table", "chain", "revision"});
		result.expected.push_back({requiredString(entry, "family"),
								   requiredString(entry, "table"),
								   requiredString(entry, "chain"),
								   requiredString(entry, "revision")});
	}
	for (const Json &entry : *changes) {
		result.changes.push_back(parseChange(entry));
	}
	return result;
}

/**
 * @brief Runs a change-set operation and maps its errors to API responses.
 * @param request Request carrying the change list as JSON.
 * @param response HTTP response to populate.
 * @param operation Safe operation identifier for diagnostics.
 * @param status Status text for a successful response.
 * @param run Operation to perform on the parsed change set.
 * @return No value; writes the response.
 */
template <typename Operation>
void runChangeSet(const httplib::Request &request, httplib::Response &response,
				  const char *operation, const char *status, Operation run) {
	try {
		const Firewall::ChangeSet changes = parseChangeSet(request);
		run(changes);
		response.set_content(
			Json{
				{ "status",				   status},
				{"changes", changes.changes.size()}
		   }
				.dump(),
			"application/json");
	} catch (const ApiError &error) {
		Detail::sendError(response, error);
	} catch (const Firewall::InvalidRuleError &error) {
		Detail::sendError(response, ValidationError(error.what()));
	} catch (const Firewall::ChangeConflictError &error) {
		Detail::sendError(response,
						  ApiError(409, "firewall_changed", error.what()));
	} catch (const Firewall::ChangeRejectedError &error) {
		Logs::Logger::API::log("request_rejected code=change_rejected",
							   Logs::Logger::Level::WARNING);
		response.status = 422;
		response.set_content(
			Json{
				{		 "error",	  error.what()},
				{		 "code", "change_rejected"},
				{"change_index",	 error.index()}
		   }
				.dump(),
			"application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, operation, error, "firewall_error",
								   "Firewall operation failed");
	}
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

void getChainRevisions(Firewall::Backend &firewall, const httplib::Request &,
					   httplib::Response &response) {
	try {
		Json chains = Json::array();
		for (const Firewall::ChainRevision &chain : firewall.chainRevisions()) {
			chains.push_back(Json{
				{	 "family",   chain.family},
				{	 "table",	  chain.table},
				{	 "chain",	  chain.chain},
				{"revision", chain.revision}
			});
		}
		response.set_content(
			Json{
				{"chains", std::move(chains)}
		 }
				.dump(),
			"application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "GET /api/v1/firewall/revisions",
								   error, "firewall_error",
								   "Firewall operation failed");
	}
}

void checkFirewallChanges(Firewall::Backend		 &firewall,
						  const httplib::Request &request,
						  httplib::Response		 &response) {
	runChangeSet(request, response, "POST /api/v1/firewall/changes/check",
				 "valid", [&](const Firewall::ChangeSet &changes) {
					 firewall.checkChanges(changes);
				 });
}

void applyFirewallChanges(Firewall::Backend		 &firewall,
						  const httplib::Request &request,
						  httplib::Response		 &response) {
	runChangeSet(request, response, "POST /api/v1/firewall/changes", "applied",
				 [&](const Firewall::ChangeSet &changes) {
					 firewall.applyChanges(changes);
				 });
}

} // namespace Http
