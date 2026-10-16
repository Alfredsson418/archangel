#pragma once

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

class Logger {
  public:
	Logger() = delete;

	enum class Level { DEBUG, INFO, WARNING, ERROR };
	enum class Type { PROGRAM, FIREWALL, API, OTHER };

	/**
	 * @brief Writes a categorized message to stdout and the configured log
	 * file.
	 * @param msg Non-sensitive diagnostic message.
	 * @param level Severity; messages below the minimum level are ignored.
	 * @param type Component category for the log entry.
	 * @return No value.
	 */
	static void log(const std::string &msg, Level level = Level::INFO,
					Type type = Type::PROGRAM) {

		if (level < _min_level)
			return;

		std::lock_guard<std::mutex> lock(_mutex);

		if (!_filestream.is_open())
			_filestream.open(_log_path, std::ios::app);

		std::string entry;
		entry.append("[" + get_time() + "] << " + level_to_string(level) + ":" +
					 type_to_string(type) + " >> " + msg);

		std::cout << entry << std::endl;
		if (_filestream.is_open()) {
			_filestream << entry << std::endl;
		}
	}

	class Firewall {
	  public:
		/**
		 * @brief Logs a firewall operation event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::FIREWALL);
		};
	};
	class Program {
	  public:
		/**
		 * @brief Logs a program lifecycle or runtime event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::PROGRAM);
		}
	};
	class API {
	  public:
		/**
		 * @brief Logs an HTTP API event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::API);
		}
	};

	/** @brief Closes the log stream if it is open. */
	~Logger() {
		if (_filestream.is_open())
			_filestream.close();
	}

  private:
	inline static std::ofstream		_filestream;
	inline static std::mutex		_mutex;
	inline static const std::string _log_path  = "./app.log";
	static const Logger::Level		_min_level = Logger::Level::DEBUG;

	/**
	 * @brief Converts a severity enum to its log label.
	 * @param level Severity to format.
	 * @return Severity label, or "UNKNOWN" for an unrecognized value.
	 */
	static std::string level_to_string(Level level) {
		switch (level) {
		case Level::DEBUG:
			return "DEBUG";
		case Level::INFO:
			return "INFO";
		case Level::WARNING:
			return "WARNING";
		case Level::ERROR:
			return "ERROR";
		}
		return "UNKNOWN";
	}

	/**
	 * @brief Converts a component enum to its log label.
	 * @param type Component category to format.
	 * @return Category label, or "OTHER" for an unrecognized value.
	 */
	static std::string type_to_string(Type type) {
		switch (type) {
		case Type::PROGRAM:
			return "PROGRAM";
		case Type::FIREWALL:
			return "FIREWALL";
		case Type::API:
			return "API";
		case Type::OTHER:
			return "OTHER";
		}
		return "OTHER";
	}

	/**
	 * @brief Formats the current system time for a log entry.
	 * @return Local time text without the trailing newline from ctime.
	 */
	static std::string get_time() {
		auto		now	 = std::chrono::system_clock::now();
		std::time_t time = std::chrono::system_clock::to_time_t(now);
		std::string ts	 = std::ctime(&time);
		ts.pop_back(); // remove trailing newline
		return ts;
	}
};
