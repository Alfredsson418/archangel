#include "http/request_audit.hpp"

#include "logs/logger.hpp"
#include "json/json.hpp"

#include <array>
#include <cstdio>
#include <openssl/rand.h>
#include <stdexcept>

namespace Http {

namespace {

/**
 * @brief Generates a random 128-bit request identifier.
 * @return 32 lowercase hexadecimal characters.
 * @throws std::runtime_error If the system random generator fails.
 */
std::string newRequestId() {
	std::array<unsigned char, 16> bytes{};
	if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
		throw std::runtime_error("Unable to generate a request identifier");
	}
	std::string id(bytes.size() * 2, '\0');
	for (std::size_t index = 0; index < bytes.size(); ++index) {
		std::snprintf(&id[index * 2], 3, "%02x", bytes[index]);
	}
	return id;
}

/**
 * @brief Builds the fields shared by every request audit record.
 * @param audit Request context.
 * @return Fields for request_id, operation, source_ip, and actor_id when known.
 */
std::map<std::string, std::string> requestFields(const RequestAudit &audit) {
	std::map<std::string, std::string> fields{
		{"request_id", audit.requestId},
		{ "operation", audit.operation},
		{ "source_ip",  audit.sourceIp},
	};
	if (!audit.actorId.empty()) {
		fields["actor_id"] = audit.actorId;
	}
	return fields;
}

} // namespace

RequestAudit beginRequestAudit(const httplib::Request &request,
							   const RoutePolicies	  &routes,
							   httplib::Response	  &response) {
	RequestAudit audit;
	audit.requestId = newRequestId();
	audit.operation =
		request.method + (routes.find(request.method, request.path) != nullptr
							  ? " " + request.path
							  : std::string(" unregistered"));
	audit.sourceIp = request.remote_addr;
	audit.started  = std::chrono::steady_clock::now();
	response.set_header(REQUEST_ID_HEADER, audit.requestId);
	return audit;
}

httplib::Server::HandlerResponse
recordAuthorizedRequest(const RequestAudit &audit,
						httplib::Response  &response) {
	if (Logs::Logger::audit({{},
							 "INFO",
							 "API",
							 "api_request_authorized",
							 requestFields(audit)})) {
		return httplib::Server::HandlerResponse::Unhandled;
	}
	response.status = 503;
	response.set_content(
		nlohmann::json{
			{"error", "Audit logging is unavailable; try again later"},
			{ "code",						 "audit_log_unavailable"}
	 }
			.dump(),
		"application/json");
	return httplib::Server::HandlerResponse::Handled;
}

void recordCompletedRequest(const RequestAudit		&audit,
							const httplib::Response &response) {
	auto fields			= requestFields(audit);
	fields["status"]	= std::to_string(response.status);
	fields["outcome"]	= response.status >= 500   ? "error"
						  : response.status >= 400 ? "rejected"
												   : "success";
	const auto duration = std::chrono::duration<double, std::milli>(
							  std::chrono::steady_clock::now() - audit.started)
							  .count();
	char formatted[32];
	std::snprintf(formatted, sizeof(formatted), "%.1f", duration);
	fields["duration_ms"] = formatted;
	Logs::Logger::audit({{},
						 response.status >= 500	  ? "ERROR"
						 : response.status >= 400 ? "WARNING"
												  : "INFO",
						 "API",
						 "api_request_completed",
						 std::move(fields)});
}

} // namespace Http
