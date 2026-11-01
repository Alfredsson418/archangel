#pragma once

#include "logs/log_sink.hpp"

#include <memory>
#include <string>

class Logger {
  public:
	Logger() = delete;

	enum class Level { DEBUG, INFO, WARNING, ERROR };
	enum class Type { PROGRAM, FIREWALL, API, OTHER };

	/**
	 * @brief Installs the structured log destination and minimum level.
	 *
	 * Until a sink is configured, messages go to standard output only.
	 * @param sink Destination for structured records, or nullptr for none.
	 * @param minimum Messages below this level are dropped.
	 * @return No value.
	 */
	static void configure(std::shared_ptr<Logging::LogSink> sink,
						  Level								minimum);

	/**
	 * @brief Converts a configured level name to a Level.
	 * @param name DEBUG, INFO, WARNING, or ERROR.
	 * @return The matching level.
	 * @throws std::invalid_argument For any other name.
	 */
	static Level parseLevel(const std::string &name);

	/**
	 * @brief Records an audit event that callers may need to fail closed on.
	 *
	 * Audit records ignore the minimum level. The record's time is set to now
	 * when unset, and it is also echoed to standard output.
	 * @param record Event with safe field values.
	 * @return False when a configured sink failed to write the record; true
	 * when it was written or no sink is configured.
	 */
	static bool audit(Logging::LogRecord record);

	/**
	 * @brief Asks the sink to reopen its destination before the next write.
	 *
	 * Async-signal-safe, so it can be called from a SIGHUP handler.
	 * @return No value.
	 */
	static void requestReopen() noexcept;

	/**
	 * @brief Writes a categorized message to stdout and the configured sink.
	 *
	 * A message written as an event name followed by key=value pairs, such as
	 * "rule_added family=inet", is recorded with that event and those fields;
	 * any other message is recorded as event "message" with a message field.
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
