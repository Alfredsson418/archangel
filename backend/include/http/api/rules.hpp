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

/**
 * @brief Writes the current revision of every chain as JSON.
 * @param firewall Firewall backend to read.
 * @param request Incoming HTTP request.
 * @param response HTTP response to populate.
 * @return No value; writes the revisions or a safe error response.
 */
void getChainRevisions(Firewall::Backend	  &firewall,
					   const httplib::Request &request,
					   httplib::Response	  &response);

/**
 * @brief Reports whether a change list would apply, without applying it.
 * @param firewall Firewall backend to check against.
 * @param request Request carrying the change list as JSON.
 * @param response HTTP response to populate.
 * @return No value; writes 200, or 400, 409, or 422 with a safe error.
 */
void checkFirewallChanges(Firewall::Backend		 &firewall,
						  const httplib::Request &request,
						  httplib::Response		 &response);

/**
 * @brief Applies a change list in one transaction, all or none.
 * @param firewall Firewall backend to change.
 * @param request Request carrying the change list as JSON.
 * @param response HTTP response to populate.
 * @return No value; writes 200, or 400, 409, or 422 with a safe error.
 */
void applyFirewallChanges(Firewall::Backend		 &firewall,
						  const httplib::Request &request,
						  httplib::Response		 &response);

} // namespace Http
