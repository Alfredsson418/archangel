#pragma once

#include "logs/log_source.hpp"

#include <string>

namespace Logging {

/**
 * @brief Reads recent Archangel events from the backend's JSONL log file.
 *
 * Each JSON line is rendered as "timestamp level category event key=value";
 * lines that are not JSON objects are shown unchanged.
 */
class ApplicationLogSource final : public LogSource {
  public:
	/**
	 * @brief Creates a reader for the configured backend log file.
	 * @param path The JSONL file written by JsonlFileSink.
	 */
	explicit ApplicationLogSource(std::string path);

	LogSourceResult read() override;

  private:
	std::string path_;
};

} // namespace Logging
