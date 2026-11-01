#pragma once

#include <chrono>
#include <map>
#include <string>

namespace Logging {

/**
 * @brief One structured log event.
 *
 * Field values must already be safe to record: never put request or response
 * bodies, query strings, submitted values, credentials, tokens, or raw
 * firewall-rule input in a record.
 */
struct LogRecord {
	std::chrono::system_clock::time_point time;
	// DEBUG, INFO, WARNING, or ERROR.
	std::string level;
	// Component that produced the event, such as PROGRAM, FIREWALL, or API.
	std::string						   category;
	std::string						   event;
	std::map<std::string, std::string> fields;
};

/**
 * @brief Destination for structured log records.
 *
 * Implementations must be safe to call from multiple threads.
 */
class LogSink {
  public:
	virtual ~LogSink() = default;

	/**
	 * @brief Appends one record to the destination.
	 * @param record Event to record.
	 * @return True when the record was handed to the destination; false when
	 * writing failed, so callers that require an audit trail can fail closed.
	 */
	virtual bool write(const LogRecord &record) = 0;

	/**
	 * @brief Reopens the destination, for example after external rotation.
	 * @return No value; failures are reported on standard error and the
	 * previous destination stays in use.
	 */
	virtual void reopen() = 0;
};

} // namespace Logging
