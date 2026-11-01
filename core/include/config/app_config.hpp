#pragma once

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace AppConfigDefaults {
#ifdef ARCHANGEL_DEV_BUILD
inline constexpr char CONFIG_PATH[] = "config.json";
inline constexpr char AUTH_DATABASE_PATH[] = "archangel.db";
inline constexpr char LOG_PATH[] = "backend.jsonl";

inline std::string executableRelativePath(const char *path) {
	std::error_code error;
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

inline std::string configPath() {
	return executableRelativePath(CONFIG_PATH);
}
inline std::string authDatabasePath() {
	return executableRelativePath(AUTH_DATABASE_PATH);
}
inline std::string logPath() {
	return executableRelativePath(LOG_PATH);
}
#else
inline constexpr char CONFIG_PATH[] = "/etc/archangel/config.json";
inline constexpr char AUTH_DATABASE_PATH[] = "/var/lib/archangel/archangel.db";
inline constexpr char LOG_PATH[] = "/var/log/archangel/backend.jsonl";

inline std::string configPath() { return CONFIG_PATH; }
inline std::string authDatabasePath() { return AUTH_DATABASE_PATH; }
inline std::string logPath() { return LOG_PATH; }
#endif
} // namespace AppConfigDefaults

namespace AppConfigLimits {
inline constexpr std::uint16_t MIN_SERVER_PORT = 1;
inline constexpr std::uint16_t MAX_SERVER_PORT = 65535;
inline constexpr std::uint16_t MIN_PASSWORD_LENGTH = 15;
inline constexpr std::uint16_t MAX_PASSWORD_LENGTH = 128;
inline constexpr std::uint32_t MIN_ARGON2ID_MEMORY_KIB = 19 * 1024;
inline constexpr std::uint32_t MAX_ARGON2ID_MEMORY_KIB = 1024 * 1024;
inline constexpr std::uint32_t MIN_ARGON2ID_ITERATIONS = 2;
inline constexpr std::uint32_t MAX_ARGON2ID_ITERATIONS = 10;
inline constexpr std::uint32_t MIN_ARGON2ID_PARALLELISM = 1;
inline constexpr std::uint32_t MAX_ARGON2ID_PARALLELISM = 8;
inline constexpr std::uint32_t MAX_SESSION_LIFETIME_SECONDS =
	365 * 24 * 60 * 60;
inline constexpr std::uint32_t MIN_RATE_LIMIT = 1;
inline constexpr std::uint32_t MAX_RATE_LIMIT = 1000000;
} // namespace AppConfigLimits

/**
 * @brief Holds the application's effective settings and their built-in defaults.
 */
struct AppConfig {
	struct Server {
		std::string bind_address = "localhost";
		std::uint16_t port = 8080;
	} server;

	struct Auth {
		std::string provider = "local";
		std::string database_path = AppConfigDefaults::authDatabasePath();
		std::uint16_t password_min_length =
			AppConfigLimits::MIN_PASSWORD_LENGTH;
		std::uint16_t password_max_length =
			AppConfigLimits::MAX_PASSWORD_LENGTH;
		std::uint32_t argon2id_memory_kib =
			AppConfigLimits::MIN_ARGON2ID_MEMORY_KIB;
		std::uint32_t argon2id_iterations =
			AppConfigLimits::MIN_ARGON2ID_ITERATIONS;
		std::uint32_t argon2id_parallelism =
			AppConfigLimits::MIN_ARGON2ID_PARALLELISM;
	} auth;

	struct Sessions {
		std::uint32_t idle_timeout_seconds = 15 * 60;
		std::uint32_t absolute_timeout_seconds = 8 * 60 * 60;
	} sessions;

	struct Tls {
		bool enabled = false;
		std::string certificate_file;
		std::string private_key_file;
	} tls;

	struct Logging {
		std::string sink = "jsonl_file";
		std::string path = AppConfigDefaults::logPath();
		std::string level = "INFO";
	} logging;

	struct RateLimits {
		std::uint32_t failed_auth_attempts = 5;
		std::uint32_t failed_auth_window_seconds = 5 * 60;
		std::uint32_t api_requests_per_minute = 120;
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
