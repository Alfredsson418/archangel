#pragma once

#include "firewall/firewall.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace Firewall::Detail {

/**
 * @brief Computes the revision of every chain in a ruleset listing.
 *
 * A revision covers the chain's definition and its rules, in order, with their
 * handles, but not counter values, so that traffic doesn't change it.
 *
 * @param ruleset nftables JSON ruleset listing.
 * @return One revision per chain.
 * @throws std::runtime_error If the listing is malformed.
 */
std::vector<ChainRevision> chainRevisions(const std::string &ruleset);

/**
 * @brief Requires that every chain a change touches is still as reviewed.
 * @param ruleset Current nftables JSON ruleset listing.
 * @param changes Change set with its expected revisions.
 * @return No value.
 * @throws InvalidRuleError If a touched chain has no expected revision.
 * @throws ChangeConflictError If a chain is missing or has a different revision.
 * @throws std::runtime_error If the listing is malformed.
 */
void requireCurrentRevisions(const std::string &ruleset,
							 const ChangeSet   &changes);

/**
 * @brief Builds the nftables transaction for the start of a change set.
 * @param ruleset Current nftables JSON ruleset listing, whose revisions the
 * caller has checked.
 * @param changes Change set to build.
 * @param count How many of its changes to include.
 * @return Serialized JSON document accepted by libnftables.
 * @throws ChangeRejectedError If a change is invalid or targets a missing rule.
 * @throws std::runtime_error If the listing is malformed.
 */
std::string buildTransaction(const std::string &ruleset,
							 const ChangeSet &changes, std::size_t count);

} // namespace Firewall::Detail
