#pragma once

#include "logs/log_sink.hpp"

#include <mutex>
#include <string>

namespace Logging {

/**
 * @brief Appends records as JSON lines to an owner-only file.
 *
 * Each record is one JSON object per line with timestamp, level, service,
 * category, and event keys followed by the record's fields. Rotation is left
 * to the operating system: rename the file, then call reopen() (the backend
 * does so on SIGHUP). Truncating the file in place (copytruncate) is not
 * supported.
 */
class JsonlFileSink final : public LogSink {
  public:
	/**
	 * @brief Opens or creates the log file.
	 * @param path File to append to. A missing parent directory is created
	 * with mode 0700; an existing parent must be owned by the effective user
	 * and not writable by group or others.
	 * @param service Value of the service key in every record.
	 * @throws std::runtime_error If the path is unsafe or cannot be opened.
	 * The file must be a regular, non-symlinked file owned by the effective
	 * user with no group or other permissions.
	 */
	JsonlFileSink(std::string path, std::string service);
	~JsonlFileSink() override;

	JsonlFileSink(const JsonlFileSink &)			= delete;
	JsonlFileSink &operator=(const JsonlFileSink &) = delete;

	bool write(const LogRecord &record) override;
	void reopen() override;

  private:
	std::string path_;
	std::string service_;
	std::mutex	mutex_;
	int			descriptor_ = -1;
	// Set after a failed write so the diagnostic is printed once per outage.
	bool failing_ = false;
};

} // namespace Logging
