#pragma once

#include "firewall/firewall.hpp"
#include "json/json.hpp"

#include <string>

namespace Firewall::Detail {

/**
 * @brief Checks that a value is safe to use as an nftables table or chain name.
 * @param value Candidate identifier.
 * @return True if it uses the accepted ASCII identifier syntax.
 */
bool isIdentifier(const std::string &value);

/**
 * @brief Validates every supported field and required match in a rule.
 * @param rule Backend-neutral rule description.
 * @return No value.
 * @throws InvalidRuleError If a field is unsupported or invalid, or the fields
 * could never match together, such as an IPv4 address with ICMPv6.
 */
void validateRule(const RuleSpec &rule);

/**
 * @brief Builds the nftables JSON statements for a validated rule.
 *
 * Builds JSON rather than command text so request values can only ever be
 * data, never nftables syntax.
 *
 * @param rule Rule that has passed validateRule.
 * @return JSON array of match statements followed by the verdict.
 */
nlohmann::json ruleExpressions(const RuleSpec &rule);

} // namespace Firewall::Detail
