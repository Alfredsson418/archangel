#include "logs/providers/jsonl_file_sink.hpp"

#include "json/json.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {

/**
 * @brief Formats a time point as UTC ISO 8601 with milliseconds.
 * @param time Time to format.
 * @return A string such as 2026-11-01T16:02:03.456Z.
 */
std::string isoTimestamp(std::chrono::system_clock::time_point time) {
	const std::time_t seconds = std::chrono::system_clock::to_time_t(time);
	const auto		  milliseconds =
		std::chrono::duration_cast<std::chrono::milliseconds>(
			time.time_since_epoch())
			.count() %
		1000;
	std::tm utc{};
	gmtime_r(&seconds, &utc);
	char			  buffer[32];
	const std::size_t length =
		std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &utc);
	char withMilliseconds[40];
	std::snprintf(withMilliseconds, sizeof(withMilliseconds), "%.*s.%03lldZ",
				  static_cast<int>(length), buffer,
				  static_cast<long long>(milliseconds));
	return withMilliseconds;
}

/**
 * @brief Opens the log file after checking its directory and ownership.
 * @param path Log file path.
 * @return An append-only descriptor for the file.
 * @throws std::runtime_error If the directory or file is unsafe or the file
 * cannot be opened.
 */
int openLogFile(const std::string &path) {
	std::filesystem::path parent = std::filesystem::path(path).parent_path();
	if (parent.empty()) {
		parent = ".";
	}
	if (!std::filesystem::exists(parent)) {
		// Create missing directories private to the service user, matching
		// the authentication database directory requirements.
		const mode_t	previousMask = umask(0077);
		std::error_code error;
		std::filesystem::create_directories(parent, error);
		umask(previousMask);
		if (error) {
			throw std::runtime_error("Unable to create log directory: " +
									 error.message());
		}
	}
	struct stat directoryInfo {};
	if (stat(parent.c_str(), &directoryInfo) != 0 ||
		!S_ISDIR(directoryInfo.st_mode) || directoryInfo.st_uid != geteuid() ||
		(directoryInfo.st_mode & 0022) != 0) {
		throw std::runtime_error(
			"Log directory must be owned by the service user and not writable "
			"by group or others");
	}

	const int descriptor =
		open(path.c_str(),
			 O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (descriptor == -1) {
		throw std::runtime_error(std::string("Unable to open log file: ") +
								 std::strerror(errno));
	}
	struct stat fileInfo {};
	if (fstat(descriptor, &fileInfo) != 0 || !S_ISREG(fileInfo.st_mode) ||
		fileInfo.st_uid != geteuid() || fileInfo.st_nlink != 1 ||
		(fileInfo.st_mode & 0077) != 0) {
		close(descriptor);
		throw std::runtime_error(
			"Log file must be a regular file owned by the service user with no "
			"group or other permissions");
	}
	return descriptor;
}

/**
 * @brief Writes a whole buffer, retrying after interrupts and short writes.
 * @param descriptor Destination file descriptor.
 * @param data Bytes to write.
 * @return True when every byte was written.
 */
bool writeAll(int descriptor, const std::string &data) {
	std::size_t written = 0;
	while (written < data.size()) {
		const ssize_t result =
			::write(descriptor, data.data() + written, data.size() - written);
		if (result == -1) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		written += static_cast<std::size_t>(result);
	}
	return true;
}

} // namespace

namespace Logging {

JsonlFileSink::JsonlFileSink(std::string path, std::string service)
	: path_(std::move(path)), service_(std::move(service)) {
	descriptor_ = openLogFile(path_);
}

JsonlFileSink::~JsonlFileSink() {
	if (descriptor_ != -1) {
		close(descriptor_);
	}
}

bool JsonlFileSink::write(const LogRecord &record) {
	nlohmann::json line;
	line["timestamp"] = isoTimestamp(record.time);
	line["level"]	  = record.level;
	line["service"]	  = service_;
	line["category"]  = record.category;
	line["event"]	  = record.event;
	for (const auto &[key, value] : record.fields) {
		// Fields never override the fixed envelope keys.
		if (!line.contains(key)) {
			line[key] = value;
		}
	}
	// Replace invalid UTF-8 rather than throwing, so one malformed value
	// cannot suppress an audit record.
	const std::string text =
		line.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) +
		"\n";

	std::lock_guard<std::mutex> lock(mutex_);
	if (writeAll(descriptor_, text)) {
		if (failing_) {
			failing_ = false;
			std::cerr << "archangel: log writes to " << path_ << " recovered\n";
		}
		return true;
	}
	if (!failing_) {
		failing_ = true;
		std::cerr << "archangel: log write to " << path_
				  << " failed: " << std::strerror(errno) << '\n';
	}
	return false;
}

void JsonlFileSink::reopen() {
	int replacement = -1;
	try {
		replacement = openLogFile(path_);
	} catch (const std::exception &error) {
		std::cerr << "archangel: log reopen failed: " << error.what() << '\n';
		return;
	}
	std::lock_guard<std::mutex> lock(mutex_);
	close(descriptor_);
	descriptor_ = replacement;
}

} // namespace Logging
