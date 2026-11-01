#include "logs/providers/application_log_source.hpp"

#include "config/app_config.hpp"
#include "json/json.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {
using Logging::LogSourceResult;

/**
 * @brief Renders one JSONL record as a readable line.
 * @param line Raw line from the log file.
 * @return "timestamp level category event key=value ..." for a JSON object,
 * with a message field shown in place of the event; otherwise the raw line.
 */
std::string renderRecord(const std::string &line) {
	const nlohmann::json record = nlohmann::json::parse(line, nullptr, false);
	if (!record.is_object()) {
		return line;
	}
	const auto text = [&record](const char *key) {
		const auto value = record.find(key);
		return value != record.end() && value->is_string()
				   ? value->get<std::string>()
				   : std::string();
	};
	std::ostringstream rendered;
	rendered << text("timestamp") << ' ' << text("level") << ' '
			 << text("category") << ' ';
	if (text("event") == "message") {
		rendered << text("message");
		return rendered.str();
	}
	rendered << text("event");
	for (const auto &[key, value] : record.items()) {
		if (key == "timestamp" || key == "level" || key == "category" ||
			key == "event" || key == "service") {
			continue;
		}
		rendered << ' ' << key << '='
				 << (value.is_string() ? value.get<std::string>()
									   : value.dump());
	}
	return rendered.str();
}
} // namespace

namespace Logging {

ApplicationLogSource::ApplicationLogSource(std::string path)
	: path_(std::move(path)) {}

LogSourceResult ApplicationLogSource::read() {
	const int file =
		open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (file == -1) {
		return {"archangel",
				"Archangel application",
				false,
				"The backend log file is not readable or has not been created.",
				{}};
	}

	struct stat fileInfo {};
	if (fstat(file, &fileInfo) == -1 || !S_ISREG(fileInfo.st_mode)) {
		close(file);
		return {"archangel",
				"Archangel application",
				false,
				"The backend log file is not a readable regular file.",
				{}};
	}
	const off_t fileSize = fileInfo.st_size;
	const off_t bytesToRead =
		std::min<off_t>(fileSize, AppConfigLimits::MAX_LOG_READ_BYTES);
	const off_t offset = fileSize - bytesToRead;
	std::string tail(static_cast<std::size_t>(bytesToRead), '\0');
	ssize_t		bytesRead = 0;
	do {
		bytesRead = pread(file, tail.data(), tail.size(), offset);
	} while (bytesRead == -1 && errno == EINTR);
	close(file);
	if (bytesRead == -1 || static_cast<std::size_t>(bytesRead) != tail.size()) {
		return {"archangel",
				"Archangel application",
				false,
				"The backend log file could not be read completely.",
				{}};
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
	std::string				 line;
	std::istringstream		 lines(tail);
	while (std::getline(lines, line)) {
		if (!line.empty()) {
			entries.push_back(renderRecord(line));
		}
	}
	std::reverse(entries.begin(), entries.end());
	return {"archangel", "Archangel application", true,
			entries.empty() ? "No application log entries yet."
							: "Showing the most recent application events.",
			std::move(entries)};
}

} // namespace Logging
