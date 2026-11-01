#include "../include/logger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>

namespace {
std::ofstream logStream;
std::mutex logMutex;
const std::string logPath = "./app.log";
constexpr Logger::Level minimumLevel = Logger::Level::DEBUG;

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

std::string currentTime() {
	const auto now = std::chrono::system_clock::now();
	const std::time_t time = std::chrono::system_clock::to_time_t(now);
	std::string timestamp = std::ctime(&time);
	if (!timestamp.empty() && timestamp.back() == '\n') {
		timestamp.pop_back();
	}
	return timestamp;
}
} // namespace

void Logger::log(const std::string &message, Level level, Type type) {
	if (level < minimumLevel) {
		return;
	}

	std::lock_guard<std::mutex> lock(logMutex);
	if (!logStream.is_open()) {
		logStream.open(logPath, std::ios::app);
	}

	const std::string entry = "[" + currentTime() + "] << " +
							  levelName(level) + ":" + typeName(type) +
							  " >> " + message;
	std::cout << entry << std::endl;
	if (logStream.is_open()) {
		logStream << entry << std::endl;
	}
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
