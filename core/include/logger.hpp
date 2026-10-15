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
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::FIREWALL);
		};
	};
	class Program {
	  public:
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::PROGRAM);
		}
	};
	class API {
	  public:
		static void log(const std::string &msg, Level level = Level::INFO) {
			Logger::log(msg, level, Type::API);
		}
	};

	~Logger() {
		if (_filestream.is_open())
			_filestream.close();
	}

  private:
	inline static std::ofstream		_filestream;
	inline static std::mutex		_mutex;
	inline static const std::string _log_path  = "./app.log";
	static const Logger::Level		_min_level = Logger::Level::DEBUG;

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

	static std::string get_time() {
		auto		now	 = std::chrono::system_clock::now();
		std::time_t time = std::chrono::system_clock::to_time_t(now);
		std::string ts	 = std::ctime(&time);
		ts.pop_back(); // remove trailing newline
		return ts;
	}
};
