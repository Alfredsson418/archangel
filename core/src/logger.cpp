#include "logger.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <mutex>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace {
std::mutex						  logMutex;
std::shared_ptr<Logging::LogSink> configuredSink;
Logger::Level					  minimumLevel = Logger::Level::INFO;
// Lock-free so requestReopen() is safe in a signal handler.
std::atomic<bool> reopenRequested{false};
static_assert(std::atomic<bool>::is_always_lock_free);

std::string levelName(Logger::Level level) {
	switch (level) {
	case Logger::Level::DEBUG:
		return "DEBUG";
	case Logger::Level::INFO:
		return "INFO";
	case Logger::Level::WARNING:
		return "WARNING";
	case Logger::Level::ERROR:
		return "ERROR";
	}
	return "UNKNOWN";
}

std::string typeName(Logger::Type type) {
	switch (type) {
	case Logger::Type::PROGRAM:
		return "PROGRAM";
	case Logger::Type::FIREWALL:
		return "FIREWALL";
	case Logger::Type::API:
		return "API";
	case Logger::Type::OTHER:
		return "OTHER";
	}
	return "OTHER";
}

/**
 * @brief Formats a record as one human-readable line for standard output.
 * @param record Record to format.
 * @return Timestamp, level, category, event, then key=value fields.
 */
std::string textLine(const Logging::LogRecord &record) {
	const std::time_t seconds =
		std::chrono::system_clock::to_time_t(record.time);
	std::tm utc{};
	gmtime_r(&seconds, &utc);
	char timestamp[32];
	std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
	std::ostringstream line;
	line << timestamp << ' ' << record.level << ' ' << record.category << ' ';
	const auto message = record.fields.find("message");
	if (record.event == "message" && message != record.fields.end()) {
		line << message->second;
		return line.str();
	}
	line << record.event;
	for (const auto &[key, value] : record.fields) {
		line << ' ' << key << '=' << value;
	}
	return line.str();
}

/**
 * @brief Builds a record from a legacy "event key=value ..." message.
 * @param message Message passed to Logger::log.
 * @param record Record whose event and fields are filled in.
 * @return No value.
 */
void parseMessage(const std::string &message, Logging::LogRecord &record) {
	static const std::regex eventPattern("^[a-z][a-z0-9_]*$");
	static const std::regex fieldPattern("^([a-z][a-z0-9_]*)=(\\S*)$");
	std::istringstream		tokens(message);
	std::string				token;
	std::map<std::string, std::string> fields;
	if (tokens >> token && std::regex_match(token, eventPattern)) {
		const std::string event = token;
		std::smatch		  match;
		bool			  structured = true;
		while (tokens >> token) {
			if (!std::regex_match(token, match, fieldPattern)) {
				structured = false;
				break;
			}
			fields[match[1]] = match[2];
		}
		if (structured) {
			record.event  = event;
			record.fields = std::move(fields);
			return;
		}
	}
	record.event			 = "message";
	record.fields["message"] = message;
}

/**
 * @brief Writes a record to standard output and the sink; caller holds
 * logMutex.
 * @param record Record to write.
 * @return False when the configured sink failed.
 */
bool writeLocked(const Logging::LogRecord &record) {
	std::cout << textLine(record) << std::endl;
	if (!configuredSink) {
		return true;
	}
	if (reopenRequested.exchange(false)) {
		configuredSink->reopen();
	}
	return configuredSink->write(record);
}
} // namespace

void Logger::configure(std::shared_ptr<Logging::LogSink> sink, Level minimum) {
	std::lock_guard<std::mutex> lock(logMutex);
	configuredSink = std::move(sink);
	minimumLevel   = minimum;
}

Logger::Level Logger::parseLevel(const std::string &name) {
	for (const Level level :
		 {Level::DEBUG, Level::INFO, Level::WARNING, Level::ERROR}) {
		if (name == levelName(level)) {
			return level;
		}
	}
	throw std::invalid_argument("Unknown log level: " + name);
}

bool Logger::audit(Logging::LogRecord record) {
	if (record.time == std::chrono::system_clock::time_point{}) {
		record.time = std::chrono::system_clock::now();
	}
	std::lock_guard<std::mutex> lock(logMutex);
	return writeLocked(record);
}

void Logger::requestReopen() noexcept { reopenRequested.store(true); }

void Logger::log(const std::string &message, Level level, Type type) {
	std::lock_guard<std::mutex> lock(logMutex);
	if (level < minimumLevel) {
		return;
	}
	Logging::LogRecord record;
	record.time		= std::chrono::system_clock::now();
	record.level	= levelName(level);
	record.category = typeName(type);
	parseMessage(message, record);
	writeLocked(record);
}

void Logger::Firewall::log(const std::string &message, Level level) {
	Logger::log(message, level, Type::FIREWALL);
}

void Logger::Program::log(const std::string &message, Level level) {
	Logger::log(message, level, Type::PROGRAM);
}

void Logger::API::log(const std::string &message, Level level) {
	Logger::log(message, level, Type::API);
}
