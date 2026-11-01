#pragma once

#include <memory>
#include <string>
#include <vector>

namespace Logging {

/**
 * @brief Recent entries from one independently identified log source.
 */
struct LogSourceResult {
	std::string id;
	std::string label;
	bool		available = false;
	// Safe explanation of the source's state, shown when it is unavailable.
	std::string detail;
	// Most recent entries, newest first.
	std::vector<std::string> entries;
};

/**
 * @brief Reader for one log source exposed by GET /api/v1/logs.
 *
 * Implementations read only their own fixed source, never arbitrary host
 * paths, and bound how much they read. readLogSources applies the shared
 * entry limits and redaction to every result.
 */
class LogSource {
  public:
	virtual ~LogSource() = default;

	/**
	 * @brief Reads the source's recent entries.
	 * @return The source's availability, explanation, and entries; failures
	 * are reported through available and detail rather than exceptions.
	 */
	virtual LogSourceResult read() = 0;
};

/**
 * @brief Reads every source and applies the shared bounds and redaction.
 * @param sources Sources in display order.
 * @return One result per source, each with at most
 * AppConfigLimits::MAX_LOG_ENTRIES entries truncated to
 * AppConfigLimits::MAX_LOG_LINE_BYTES and common credential values redacted.
 */
std::vector<LogSourceResult>
readLogSources(const std::vector<std::unique_ptr<LogSource>> &sources);

} // namespace Logging
