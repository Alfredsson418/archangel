#include "logs/providers/nftables_journal_source.hpp"

#include "config/app_config.hpp"
#include "logs/logger.hpp"
#include "json/json.hpp"

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <utility>

namespace {
using Logging::LogSourceResult;
using Json = nlohmann::json;

bool hasNftablesLogRules(Firewall &firewall) {
	const Json ruleset = Json::parse(firewall.listRules());
	if (!ruleset.is_object()) {
		throw std::runtime_error("Invalid nftables ruleset");
	}
	const auto nftables = ruleset.find("nftables");
	if (nftables == ruleset.end() || !nftables->is_array()) {
		throw std::runtime_error("Invalid nftables ruleset");
	}
	for (const Json &entry : *nftables) {
		if (!entry.is_object()) {
			continue;
		}
		const auto rule = entry.find("rule");
		if (rule == entry.end() || !rule->is_object()) {
			continue;
		}
		const auto expression = rule->find("expr");
		if (expression == rule->end() || !expression->is_array()) {
			continue;
		}
		for (const Json &statement : *expression) {
			if (statement.is_object() && statement.contains("log")) {
				return true;
			}
		}
	}
	return false;
}

bool readBoundedLine(FILE *stream, std::string &line) {
	line.clear();
	bool readAny = false;
	for (;;) {
		const int character = std::fgetc(stream);
		if (character == EOF || character == '\n') {
			return readAny;
		}
		readAny = true;
		if (line.size() < AppConfigLimits::MAX_LOG_LINE_BYTES) {
			line.push_back(static_cast<char>(character));
		}
	}
}

LogSourceResult readNftablesJournal() {
	FILE *pipe = popen("journalctl --dmesg --output=short-iso --no-pager "
					   "--lines=500 2>/dev/null",
					   "r");
	if (pipe == nullptr) {
		return {"nftables",
				"nftables packet logs",
				false,
				"The host kernel journal could not be opened.",
				{}};
	}

	std::vector<std::string> entries;
	std::string				 line;
	while (readBoundedLine(pipe, line)) {
		if (line.find("SRC=") == std::string::npos ||
			line.find("DST=") == std::string::npos ||
			line.find("PROTO=") == std::string::npos) {
			continue;
		}
		entries.push_back(line);
		// Keep only what can be returned; older lines are dropped.
		if (entries.size() > AppConfigLimits::MAX_LOG_ENTRIES) {
			entries.erase(entries.begin());
		}
	}
	const int result = pclose(pipe);
	if (result == -1 || !WIFEXITED(result) || WEXITSTATUS(result) != 0) {
		return {"nftables",
				"nftables packet logs",
				false,
				"The host kernel journal is unavailable or access was denied.",
				{}};
	}

	std::reverse(entries.begin(), entries.end());
	return {"nftables", "nftables packet logs", true,
			entries.empty()
				? "No recent nftables packet log entries found."
				: "Showing recent packet events from the host kernel journal.",
			std::move(entries)};
}
} // namespace

namespace Logging {

NftablesJournalSource::NftablesJournalSource(Firewall &firewall)
	: firewall_(firewall) {}

LogSourceResult NftablesJournalSource::read() {
	try {
		if (hasNftablesLogRules(firewall_)) {
			return readNftablesJournal();
		}
	} catch (const std::exception &) {
		Logger::API::log("log_source_unavailable source=nftables",
						 Logger::Level::WARNING);
		return {"nftables",
				"nftables packet logs",
				false,
				"The active nftables ruleset could not be inspected.",
				{}};
	}
	return {"nftables",
			"nftables packet logs",
			false,
			"No nftables log statements are present in the active ruleset.",
			{}};
}

} // namespace Logging
