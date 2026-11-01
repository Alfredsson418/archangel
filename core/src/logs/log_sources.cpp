#include "log_sources.hpp"

#include "../../include/config/app_config.hpp"
#include "../../lib/json/json.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace {
using BackendLogSources::Source;
using Json = nlohmann::json;

std::string redactSensitiveValues(const std::string &line) {
	static const std::regex quotedCredentialPattern(
		R"(((password|token|secret|authorization|api[_-]?key)["']?\s*[:=]\s*)("[^"]*"|'[^']*'))",
		std::regex_constants::icase);
	static const std::regex authorizationPattern(
		R"((authorization(["']?\s*[:=]\s*["']?))((bearer|basic)\s+)?([^"'\s,;}]+))",
		std::regex_constants::icase);
	const std::string quotedSanitized =
		std::regex_replace(line, quotedCredentialPattern, "$1\"[REDACTED]\"");
	const std::string sanitized = std::regex_replace(
		quotedSanitized, authorizationPattern, "$1[REDACTED]");
	static const std::regex credentialPattern(
		R"((password|token|secret|api[_-]?key)(["']?\s*[:=]\s*["']?)([^"'\s,;}]+))",
		std::regex_constants::icase);
	return std::regex_replace(sanitized, credentialPattern, "$1$2[REDACTED]");
}

Source readArchangelLog() {
	std::string path;
	try {
		path = AppConfigDefaults::applicationLogPath();
	} catch (const std::exception &) {
		return {"archangel",
				"Archangel application",
				false,
				"The backend log file location could not be resolved.",
				{}};
	}
	const int file =
		open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (file == -1) {
		return {"archangel", "Archangel application", false,
				"The backend log file is not readable or has not been created.",
				{}};
	}

	struct stat fileInfo {};
	if (fstat(file, &fileInfo) == -1 || !S_ISREG(fileInfo.st_mode)) {
		close(file);
		return {"archangel", "Archangel application", false,
				"The backend log file is not a readable regular file.", {}};
	}
	const off_t fileSize = fileInfo.st_size;
	const off_t bytesToRead =
		std::min<off_t>(fileSize, AppConfigLimits::MAX_LOG_READ_BYTES);
	const off_t offset = fileSize - bytesToRead;
	std::string tail(static_cast<std::size_t>(bytesToRead), '\0');
	ssize_t bytesRead = 0;
	do {
		bytesRead = pread(file, tail.data(), tail.size(), offset);
	} while (bytesRead == -1 && errno == EINTR);
	close(file);
	if (bytesRead == -1 || static_cast<std::size_t>(bytesRead) != tail.size()) {
		return {"archangel", "Archangel application", false,
				"The backend log file could not be read completely.", {}};
	}
	if (offset > 0) {
		const std::size_t firstNewline = tail.find('\n');
		if (firstNewline == std::string::npos) {
			tail.clear();
		} else {
			tail.erase(0, firstNewline + 1);
		}
	}

	std::vector<std::string> entries;
	std::string line;
	std::istringstream lines(tail);
	while (std::getline(lines, line)) {
		if (line.size() > AppConfigLimits::MAX_LOG_LINE_BYTES) {
			line.resize(AppConfigLimits::MAX_LOG_LINE_BYTES);
		}
		entries.push_back(redactSensitiveValues(line));
		if (entries.size() > AppConfigLimits::MAX_LOG_ENTRIES) {
			entries.erase(entries.begin());
		}
	}
	std::reverse(entries.begin(), entries.end());
	return {"archangel",
			"Archangel application",
			true,
			entries.empty() ? "No application log entries yet."
							: "Showing the most recent application events.",
			std::move(entries)};
}

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

Source readNftablesLog() {
	FILE *pipe = popen("journalctl --dmesg --output=short-iso --no-pager "
					   "--lines=500 2>/dev/null",
					   "r");
	if (pipe == nullptr) {
		return {"nftables", "nftables packet logs", false,
				"The host kernel journal could not be opened.", {}};
	}

	std::vector<std::string> entries;
	std::string line;
	while (readBoundedLine(pipe, line)) {
		if (line.find("SRC=") == std::string::npos ||
			line.find("DST=") == std::string::npos ||
			line.find("PROTO=") == std::string::npos) {
			continue;
		}
		entries.push_back(redactSensitiveValues(line));
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
	return {"nftables",
			"nftables packet logs",
			true,
			entries.empty()
				? "No recent nftables packet log entries found."
				: "Showing recent packet events from the host kernel journal.",
			std::move(entries)};
}
} // namespace

namespace BackendLogSources {

ReadResult readSources(Firewall &firewall) {
	ReadResult result;
	result.sources.push_back(readArchangelLog());
	try {
		if (hasNftablesLogRules(firewall)) {
			result.sources.push_back(readNftablesLog());
		} else {
			result.sources.push_back(
				{"nftables",
				 "nftables packet logs",
				 false,
				 "No nftables log statements are present in the active ruleset.",
				 {}});
		}
	} catch (const std::exception &) {
		result.rulesetUnavailable = true;
		result.sources.push_back(
			{"nftables",
			 "nftables packet logs",
			 false,
			 "The active nftables ruleset could not be inspected.",
			 {}});
	}
	return result;
}

} // namespace BackendLogSources
