#pragma once

#include <string>

class Logger {
  public:
	Logger() = delete;

	enum class Level { DEBUG, INFO, WARNING, ERROR };
	enum class Type { PROGRAM, FIREWALL, API, OTHER };

	/**
	 * @brief Writes a categorized message to stdout and the application log.
	 * @param msg Non-sensitive diagnostic message.
	 * @param level Severity; messages below the minimum level are ignored.
	 * @param type Component category for the log entry.
	 * @return No value.
	 */
	static void log(const std::string &msg, Level level = Level::INFO,
					Type type = Type::PROGRAM);

	class Firewall {
	  public:
		/**
		 * @brief Logs a firewall operation event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO);
	};

	class Program {
	  public:
		/**
		 * @brief Logs a program lifecycle or runtime event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO);
	};

	class API {
	  public:
		/**
		 * @brief Logs an HTTP API event.
		 * @param msg Non-sensitive event details.
		 * @param level Severity of the event.
		 * @return No value.
		 */
		static void log(const std::string &msg, Level level = Level::INFO);
	};
};
