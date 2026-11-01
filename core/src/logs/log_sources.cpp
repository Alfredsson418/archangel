#include "config/app_config.hpp"
#include "logs/providers/log_source.hpp"

#include <regex>
#include <string>

namespace {

/**
 * @brief Replaces common credential values in a log line.
 * @param line Entry from any log source.
 * @return The line with password, token, secret, API key, and Authorization
 * values replaced by [REDACTED].
 */
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
} // namespace

namespace Logging {

std::vector<LogSourceResult>
readLogSources(const std::vector<std::unique_ptr<LogSource>> &sources) {
	std::vector<LogSourceResult> results;
	results.reserve(sources.size());
	for (const auto &source : sources) {
		LogSourceResult result = source->read();
		if (result.entries.size() > AppConfigLimits::MAX_LOG_ENTRIES) {
			result.entries.resize(AppConfigLimits::MAX_LOG_ENTRIES);
		}
		for (std::string &entry : result.entries) {
			if (entry.size() > AppConfigLimits::MAX_LOG_LINE_BYTES) {
				entry.resize(AppConfigLimits::MAX_LOG_LINE_BYTES);
			}
			entry = redactSensitiveValues(entry);
		}
		results.push_back(std::move(result));
	}
	return results;
}

} // namespace Logging
