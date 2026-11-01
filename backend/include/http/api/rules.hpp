#pragma once

#include "cpp-httplib/cpp-httplib.hpp"
#include "firewall/firewall.hpp"

namespace Http {

/**
 * @brief Writes the active ruleset as a JSON HTTP response.
 * @param firewall Backend from which to retrieve rules.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes success or error details to response.
 */
void getRules(Firewall::Backend &firewall, const httplib::Request &request,
			  httplib::Response &response);

/**
 * @brief Validates a structured JSON rule request and applies the rule.
 * @param firewall Backend on which to add the rule.
 * @param request Request containing the JSON rule description.
 * @param response HTTP response to populate.
 * @return No value; writes the creation result or error to response.
 */
void createRule(Firewall::Backend &firewall, const httplib::Request &request,
				httplib::Response &response);

/**
 * @brief Validates a JSON rule identifier and deletes that rule.
 * @param firewall Backend from which to delete the rule.
 * @param request Request containing family, table, chain, and numeric handle.
 * @param response HTTP response to populate.
 * @return No value; writes the deletion result or error to response.
 */
void deleteRule(Firewall::Backend &firewall, const httplib::Request &request,
				httplib::Response &response);

} // namespace Http
