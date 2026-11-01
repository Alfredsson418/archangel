#pragma once

#include "cpp-httplib/cpp-httplib.hpp"
#include "http/authentication.hpp"

#include <chrono>
#include <string>

namespace Http {

// Response header carrying the backend's identifier for a request, so clients
// can correlate their own logs with the backend audit record.
inline constexpr char REQUEST_ID_HEADER[] = "X-Request-ID";

/**
 * @brief Audit context for one request, filled in while it is processed.
 */
struct RequestAudit {
	std::string requestId;
	// Authenticated account ID; empty for unauthenticated requests.
	std::string actorId;
	// "METHOD /registered/path", or "METHOD unregistered" so attacker-chosen
	// paths are never recorded.
	std::string							  operation;
	std::string							  sourceIp;
	std::chrono::steady_clock::time_point started;
};

/**
 * @brief Starts auditing a request and returns its ID to the client.
 * @param request Incoming request.
 * @param routes Registered route policies, used to label the operation.
 * @param response Response that receives the X-Request-ID header.
 * @return The new request's audit context.
 */
RequestAudit beginRequestAudit(const httplib::Request &request,
							   const RoutePolicies	  &routes,
							   httplib::Response	  &response);

/**
 * @brief Records that an authorized request is about to run; fails closed.
 *
 * Call after authorization succeeds and before the route handler, for every
 * route except liveness, so no protected action proceeds unrecorded.
 * @param audit Context from beginRequestAudit with the actor filled in.
 * @param response Response to populate when the record cannot be written.
 * @return Unhandled when the record was written; Handled with HTTP 503 when
 * the audit log is unavailable.
 */
httplib::Server::HandlerResponse
recordAuthorizedRequest(const RequestAudit &audit, httplib::Response &response);

/**
 * @brief Records a finished request's status, outcome, and duration.
 * @param audit Context from beginRequestAudit.
 * @param response Final response.
 * @return No value; a failed write is reported on standard error by the
 * sink, because the response has already been decided.
 */
void recordCompletedRequest(const RequestAudit		&audit,
							const httplib::Response &response);

} // namespace Http
