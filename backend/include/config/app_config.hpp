#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace Config {

namespace Defaults {
#ifdef ARCHANGEL_DEV_BUILD
inline constexpr char CONFIG_PATH[]		   = "config.json";
inline constexpr char AUTH_DATABASE_PATH[] = "archangel.db";
inline constexpr char LOG_PATH[]		   = "backend.jsonl";

inline std::string executableRelativePath(const char *path) {
	std::error_code				error;
	const std::filesystem::path executable =
		std::filesystem::read_symlink("/proc/self/exe", error);
	if (error || executable.empty()) {
		throw std::runtime_error(
			"Unable to resolve executable path for development defaults");
	}
	return (executable.parent_path() / ".archangel-dev" / path)
		.lexically_normal()
		.string();
}

inline std::string configPath() { return executableRelativePath(CONFIG_PATH); }
inline std::string authDatabasePath() {
	return executableRelativePath(AUTH_DATABASE_PATH);
}
inline std::string logPath() { return executableRelativePath(LOG_PATH); }
#else
inline constexpr char CONFIG_PATH[]		   = "/etc/archangel/config.json";
inline constexpr char AUTH_DATABASE_PATH[] = "/var/lib/archangel/archangel.db";
inline constexpr char LOG_PATH[]		   = "/var/log/archangel/backend.jsonl";

inline std::string configPath() { return CONFIG_PATH; }
inline std::string authDatabasePath() { return AUTH_DATABASE_PATH; }
inline std::string logPath() { return LOG_PATH; }
#endif

inline constexpr std::chrono::seconds SESSION_IDLE_TIMEOUT =
	std::chrono::minutes(15);
inline constexpr std::chrono::seconds SESSION_ABSOLUTE_TIMEOUT =
	std::chrono::hours(8);
} // namespace Defaults

// Single definitions of the backend's limits. Modules read these rather than
// keeping local copies.
namespace Limits {
inline constexpr std::uint16_t MIN_SERVER_PORT = 1;
inline constexpr std::uint16_t MAX_SERVER_PORT = 65535;

// Local-account passwords. Debug builds allow short passwords for local
// testing; release builds keep the agreed 15-character floor.
#ifdef ARCHANGEL_DEV_BUILD
inline constexpr std::uint16_t MIN_PASSWORD_LENGTH = 1;
#else
inline constexpr std::uint16_t MIN_PASSWORD_LENGTH = 15;
#endif
inline constexpr std::uint16_t MAX_PASSWORD_LENGTH = 128;
// Encoded size bound: each code point takes at most four UTF-8 bytes.
inline constexpr std::size_t MAX_PASSWORD_BYTES = 4 * MAX_PASSWORD_LENGTH;

inline constexpr std::size_t MIN_USERNAME_LENGTH   = 3;
inline constexpr std::size_t MAX_USERNAME_LENGTH   = 64;
inline constexpr std::size_t MAX_ACCOUNT_ID_LENGTH = 64;

// Session and setup tokens are random values sent as lowercase hex.
inline constexpr std::size_t TOKEN_BYTES	  = 32;
inline constexpr std::size_t TOKEN_HEX_LENGTH = 2 * TOKEN_BYTES;
// Longest credential accepted from an Authorization header before lookup.
inline constexpr std::size_t  MAX_BEARER_TOKEN_LENGTH			   = 256;
inline constexpr std::int64_t ACCOUNT_SETUP_TOKEN_LIFETIME_SECONDS = 60 * 60;

// Argon2id bounds; the minimums are the OWASP baseline defaults.
inline constexpr std::uint32_t MIN_ARGON2ID_MEMORY_KIB	= 19 * 1024;
inline constexpr std::uint32_t MAX_ARGON2ID_MEMORY_KIB	= 1024 * 1024;
inline constexpr std::uint32_t MIN_ARGON2ID_ITERATIONS	= 2;
inline constexpr std::uint32_t MAX_ARGON2ID_ITERATIONS	= 10;
inline constexpr std::uint32_t MIN_ARGON2ID_PARALLELISM = 1;
inline constexpr std::uint32_t MAX_ARGON2ID_PARALLELISM = 8;

inline constexpr std::uint32_t MAX_SESSION_LIFETIME_SECONDS =
	365 * 24 * 60 * 60;
inline constexpr std::uint32_t MIN_RATE_LIMIT = 1;
inline constexpr std::uint32_t MAX_RATE_LIMIT = 1000000;
// Distinct keys an in-memory rate limiter tracks at once; new keys are denied
// while the table is full of unexpired windows.
inline constexpr std::size_t MAX_TRACKED_RATE_LIMIT_KEYS = 8192;
inline constexpr std::size_t MAX_TRACKED_LOGIN_SOURCES	 = 4096;

// Request and file size bounds.
inline constexpr std::size_t  MAX_LOGIN_BODY_BYTES			   = 16 * 1024;
inline constexpr std::size_t  MAX_ACCOUNT_BODY_BYTES		   = 16 * 1024;
inline constexpr std::int64_t MAX_RUNTIME_CONFIG_BYTES		   = 1024 * 1024;
inline constexpr std::size_t  MAX_RUNTIME_CONFIG_STRING_LENGTH = 4096;
inline constexpr std::int64_t MAX_FIREWALL_BUNDLE_BYTES = 16 * 1024 * 1024;
// Operator-provided list of common or compromised passwords, held in memory.
inline constexpr std::int64_t MAX_PASSWORD_BLOCKLIST_BYTES = 64 * 1024 * 1024;

// Bounds for log sources returned by GET /api/v1/logs.
inline constexpr std::size_t  MAX_LOG_ENTRIES	 = 100;
inline constexpr std::int64_t MAX_LOG_READ_BYTES = 512 * 1024;
inline constexpr std::size_t  MAX_LOG_LINE_BYTES = 4096;

inline constexpr std::size_t MAX_FIREWALL_IDENTIFIER_LENGTH = 64;
// Linux limits interface names to 15 characters (IFNAMSIZ minus the NUL).
inline constexpr std::size_t MAX_INTERFACE_NAME_LENGTH = 15;
// new, established, related, and invalid.
inline constexpr std::size_t MAX_CONNECTION_STATES = 4;
} // namespace Limits

/**
 * @brief Holds the application's effective settings and their built-in
 * defaults.
 */
struct AppConfig {
	struct Server {
		std::string	  bind_address = "localhost";
		std::uint16_t port		   = 8080;
	} server;

	struct Auth {
		std::string	  provider			   = "local";
		std::string	  database_path		   = Defaults::authDatabasePath();
		std::uint16_t password_min_length  = Limits::MIN_PASSWORD_LENGTH;
		std::uint16_t password_max_length  = Limits::MAX_PASSWORD_LENGTH;
		std::uint32_t argon2id_memory_kib  = Limits::MIN_ARGON2ID_MEMORY_KIB;
		std::uint32_t argon2id_iterations  = Limits::MIN_ARGON2ID_ITERATIONS;
		std::uint32_t argon2id_parallelism = Limits::MIN_ARGON2ID_PARALLELISM;
		// Empty disables the blocklist check.
		std::string password_blocklist_path;
	} auth;

	struct Sessions {
		std::uint32_t idle_timeout_seconds =
			static_cast<std::uint32_t>(Defaults::SESSION_IDLE_TIMEOUT.count());
		std::uint32_t absolute_timeout_seconds = static_cast<std::uint32_t>(
			Defaults::SESSION_ABSOLUTE_TIMEOUT.count());
	} sessions;

	struct Tls {
		bool		enabled = false;
		std::string certificate_file;
		std::string private_key_file;
	} tls;

	struct Logging {
		std::string sink  = "jsonl_file";
		std::string path  = Defaults::logPath();
		std::string level = "INFO";
	} logging;

	struct RateLimits {
		std::uint32_t failed_auth_attempts			= 5;
		std::uint32_t failed_auth_window_seconds	= 5 * 60;
		std::uint32_t api_requests_per_minute		= 120;
		std::uint32_t firewall_mutations_per_minute = 30;
	} rate_limits;
};

/**
 * @brief Validates effective application settings before they are used.
 * @param config Settings after runtime-file and CLI overrides are applied.
 * @return No value.
 * @throws std::runtime_error If any setting is invalid.
 */
void validateAppConfig(const AppConfig &config);

} // namespace Config
