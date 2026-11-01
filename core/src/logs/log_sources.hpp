#pragma once

#include "../../include/firewall/providers/firewall.hpp"

#include <string>
#include <vector>

namespace BackendLogSources {

struct Source {
	std::string				 id;
	std::string				 label;
	bool					 available;
	std::string				 detail;
	std::vector<std::string> entries;
};

struct ReadResult {
	std::vector<Source> sources;
	bool				rulesetUnavailable = false;
};

/**
 * @brief Reads bounded application and nftables log sources.
 * @param firewall Backend whose active ruleset determines packet-log status.
 * @return Source data and whether the active ruleset could not be inspected.
 */
ReadResult readSources(Firewall &firewall);

} // namespace BackendLogSources
