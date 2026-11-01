#include "config/runtime_config.hpp"
#include "json/json.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <unistd.h>

namespace Config {

namespace {
using Json = nlohmann::json;
void rejectUnknownKeys(const Json						  &object,
					   std::initializer_list<const char *> allowed,
					   const char						  *description) {
	for (auto key = object.begin(); key != object.end(); ++key) {
		bool known = false;
		for (const char *candidate : allowed) {
			known = known || key.key() == candidate;
		}
		if (!known) {
			throw std::runtime_error(std::string(description) +
									 " contains unknown key: " + key.key());
		}
	}
}

const Json *optionalObject(const Json &document, const char *key) {
	const auto field = document.find(key);
	if (field == document.end()) {
		return nullptr;
	}
	if (!field->is_object()) {
		throw std::runtime_error(std::string("Runtime config ") + key +
								 " must be an object");
	}
	return &*field;
}

std::string requiredString(const Json &object, const char *key,
						   const std::string &current,
						   const char		 *description) {
	const auto field = object.find(key);
	if (field == object.end()) {
		return current;
	}
	if (!field->is_string()) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " must be a string");
	}
	const std::string value = field->get<std::string>();
	if (value.empty() || value.find('\0') != std::string::npos ||
		value.size() > Limits::MAX_RUNTIME_CONFIG_STRING_LENGTH) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " is invalid");
	}
	return value;
}

bool requiredBoolean(const Json &object, const char *key, bool current,
					 const char *description) {
	const auto field = object.find(key);
	if (field == object.end()) {
		return current;
	}
	if (!field->is_boolean()) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " must be a boolean");
	}
	return field->get<bool>();
}

std::uint64_t unsignedInteger(const Json &object, const char *key,
							  std::uint64_t current, const char *description) {
	const auto field = object.find(key);
	if (field == object.end()) {
		return current;
	}
	if (!field->is_number_integer()) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " must be a positive integer");
	}
	try {
		const std::int64_t value = field->get<std::int64_t>();
		if (value < 0) {
			throw std::runtime_error(std::string(description) + "." + key +
									 " must be a positive integer");
		}
		return static_cast<std::uint64_t>(value);
	} catch (const Json::exception &) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " is outside the supported range");
	}
}

std::uint32_t boundedInteger(const Json &object, const char *key,
							 std::uint32_t current, std::uint32_t minimum,
							 std::uint32_t maximum, const char *description) {
	const std::uint64_t value =
		unsignedInteger(object, key, current, description);
	if (value < minimum || value > maximum) {
		throw std::runtime_error(std::string(description) + "." + key +
								 " is outside the supported range");
	}
	return static_cast<std::uint32_t>(value);
}

Json parseJson(const std::string &content) {
	try {
		return Json::parse(content);
	} catch (const Json::exception &error) {
		throw std::runtime_error(std::string("Invalid runtime config JSON: ") +
								 error.what());
	}
}

void validateConfig(const AppConfig &config) {
	if (config.server.bind_address.empty() ||
		config.server.bind_address.size() > 255 ||
		config.server.bind_address.find_first_of(" \t\r\n") !=
			std::string::npos ||
		config.server.bind_address.find('\0') != std::string::npos ||
		config.server.port < Limits::MIN_SERVER_PORT) {
		throw std::runtime_error(
			"Runtime config server.bind_address is invalid");
	}
	if (config.auth.provider != "local") {
		throw std::runtime_error("Runtime config auth.provider must be local");
	}
	if (config.auth.database_path.empty() ||
		config.auth.database_path.find('\0') != std::string::npos) {
		throw std::runtime_error(
			"Runtime config auth.database_path is invalid");
	}
	if (config.auth.password_blocklist_path.find('\0') != std::string::npos) {
		throw std::runtime_error(
			"Runtime config auth.password_blocklist_path is invalid");
	}
	if (config.auth.password_min_length < Limits::MIN_PASSWORD_LENGTH ||
		config.auth.password_max_length > Limits::MAX_PASSWORD_LENGTH ||
		config.auth.password_min_length > config.auth.password_max_length) {
		throw std::runtime_error(
			"Runtime config password minimum must not exceed its maximum");
	}
	if (config.auth.argon2id_memory_kib < Limits::MIN_ARGON2ID_MEMORY_KIB ||
		config.auth.argon2id_memory_kib > Limits::MAX_ARGON2ID_MEMORY_KIB ||
		config.auth.argon2id_iterations < Limits::MIN_ARGON2ID_ITERATIONS ||
		config.auth.argon2id_iterations > Limits::MAX_ARGON2ID_ITERATIONS ||
		config.auth.argon2id_parallelism < Limits::MIN_ARGON2ID_PARALLELISM ||
		config.auth.argon2id_parallelism > Limits::MAX_ARGON2ID_PARALLELISM ||
		config.auth.argon2id_memory_kib <
			config.auth.argon2id_parallelism * 8) {
		throw std::runtime_error("Runtime config Argon2id parameters are "
								 "outside the supported range");
	}
	if (config.sessions.idle_timeout_seconds == 0 ||
		config.sessions.absolute_timeout_seconds == 0 ||
		config.sessions.idle_timeout_seconds >=
			config.sessions.absolute_timeout_seconds ||
		config.sessions.absolute_timeout_seconds >
			Limits::MAX_SESSION_LIFETIME_SECONDS) {
		throw std::runtime_error(
			"Runtime config session lifetimes are invalid");
	}
	if (config.tls.enabled && (config.tls.certificate_file.empty() ||
							   config.tls.private_key_file.empty())) {
		throw std::runtime_error("Enabled runtime TLS requires "
								 "certificate_file and private_key_file");
	}
	if (!config.tls.certificate_file.empty() &&
		!config.tls.private_key_file.empty() &&
		config.tls.certificate_file == config.tls.private_key_file) {
		throw std::runtime_error(
			"Runtime TLS certificate and private key paths must differ");
	}
	if (config.logging.sink != "jsonl_file") {
		throw std::runtime_error(
			"Runtime config logging.sink must be jsonl_file");
	}
	if (config.logging.path.empty() ||
		config.logging.path.find('\0') != std::string::npos) {
		throw std::runtime_error("Runtime config logging.path is invalid");
	}
	if (config.logging.level != "DEBUG" && config.logging.level != "INFO" &&
		config.logging.level != "WARNING" && config.logging.level != "ERROR") {
		throw std::runtime_error("Runtime config logging.level must be DEBUG, "
								 "INFO, WARNING, or ERROR");
	}
	if (config.rate_limits.failed_auth_attempts < Limits::MIN_RATE_LIMIT ||
		config.rate_limits.failed_auth_attempts > Limits::MAX_RATE_LIMIT ||
		config.rate_limits.failed_auth_window_seconds <
			Limits::MIN_RATE_LIMIT ||
		config.rate_limits.failed_auth_window_seconds >
			Limits::MAX_SESSION_LIFETIME_SECONDS ||
		config.rate_limits.api_requests_per_minute < Limits::MIN_RATE_LIMIT ||
		config.rate_limits.api_requests_per_minute > Limits::MAX_RATE_LIMIT ||
		config.rate_limits.firewall_mutations_per_minute <
			Limits::MIN_RATE_LIMIT ||
		config.rate_limits.firewall_mutations_per_minute >
			Limits::MAX_RATE_LIMIT) {
		throw std::runtime_error(
			"Runtime config rate limits are outside the supported range");
	}
}

} // namespace

void validateAppConfig(const AppConfig &config) { validateConfig(config); }

AppConfig parseRuntimeConfig(const std::string &content) {
	const Json document = parseJson(content);
	if (!document.is_object()) {
		throw std::runtime_error("Runtime config must be a JSON object");
	}
	rejectUnknownKeys(document,
					  {"format", "version", "server", "auth", "sessions", "tls",
					   "logging", "rate_limits"},
					  "Runtime config");
	if (!document.contains("format") || !document["format"].is_string() ||
		document["format"] != "archangel-runtime-config" ||
		!document.contains("version") ||
		!document["version"].is_number_integer() || document["version"] != 1) {
		throw std::runtime_error("Runtime config must use format "
								 "archangel-runtime-config version 1");
	}

	AppConfig config;
	if (const Json *server = optionalObject(document, "server")) {
		rejectUnknownKeys(*server, {"bind_address", "port"},
						  "Runtime config server");
		config.server.bind_address = requiredString(
			*server, "bind_address", config.server.bind_address, "server");
		config.server.port = static_cast<std::uint16_t>(boundedInteger(
			*server, "port", config.server.port, Limits::MIN_SERVER_PORT,
			Limits::MAX_SERVER_PORT, "server"));
	}
	if (const Json *auth = optionalObject(document, "auth")) {
		rejectUnknownKeys(*auth,
						  {"provider", "database_path", "password_min_length",
						   "password_max_length", "password_blocklist_path",
						   "argon2id"},
						  "Runtime config auth");
		config.auth.provider =
			requiredString(*auth, "provider", config.auth.provider, "auth");
		config.auth.database_path = requiredString(
			*auth, "database_path", config.auth.database_path, "auth");
		config.auth.password_min_length =
			static_cast<std::uint16_t>(boundedInteger(
				*auth, "password_min_length", config.auth.password_min_length,
				Limits::MIN_PASSWORD_LENGTH, Limits::MAX_PASSWORD_LENGTH,
				"auth"));
		config.auth.password_max_length =
			static_cast<std::uint16_t>(boundedInteger(
				*auth, "password_max_length", config.auth.password_max_length,
				config.auth.password_min_length, Limits::MAX_PASSWORD_LENGTH,
				"auth"));
		if (auth->contains("password_blocklist_path")) {
			config.auth.password_blocklist_path =
				requiredString(*auth, "password_blocklist_path", {}, "auth");
		}
		if (const Json *argon = optionalObject(*auth, "argon2id")) {
			rejectUnknownKeys(*argon,
							  {"memory_kib", "iterations", "parallelism"},
							  "Runtime config auth.argon2id");
			config.auth.argon2id_memory_kib = boundedInteger(
				*argon, "memory_kib", config.auth.argon2id_memory_kib,
				Limits::MIN_ARGON2ID_MEMORY_KIB,
				Limits::MAX_ARGON2ID_MEMORY_KIB, "auth.argon2id");
			config.auth.argon2id_iterations = boundedInteger(
				*argon, "iterations", config.auth.argon2id_iterations,
				Limits::MIN_ARGON2ID_ITERATIONS,
				Limits::MAX_ARGON2ID_ITERATIONS, "auth.argon2id");
			config.auth.argon2id_parallelism = boundedInteger(
				*argon, "parallelism", config.auth.argon2id_parallelism,
				Limits::MIN_ARGON2ID_PARALLELISM,
				Limits::MAX_ARGON2ID_PARALLELISM, "auth.argon2id");
		}
	}
	if (const Json *sessions = optionalObject(document, "sessions")) {
		rejectUnknownKeys(*sessions,
						  {"idle_timeout_seconds", "absolute_timeout_seconds"},
						  "Runtime config sessions");
		config.sessions.idle_timeout_seconds =
			boundedInteger(*sessions, "idle_timeout_seconds",
						   config.sessions.idle_timeout_seconds, 1,
						   Limits::MAX_SESSION_LIFETIME_SECONDS, "sessions");
		config.sessions.absolute_timeout_seconds =
			boundedInteger(*sessions, "absolute_timeout_seconds",
						   config.sessions.absolute_timeout_seconds, 1,
						   Limits::MAX_SESSION_LIFETIME_SECONDS, "sessions");
	}
	if (const Json *tls = optionalObject(document, "tls")) {
		rejectUnknownKeys(*tls,
						  {"enabled", "certificate_file", "private_key_file"},
						  "Runtime config tls");
		config.tls.enabled =
			requiredBoolean(*tls, "enabled", config.tls.enabled, "tls");
		if (tls->contains("certificate_file")) {
			config.tls.certificate_file =
				requiredString(*tls, "certificate_file", {}, "tls");
		}
		if (tls->contains("private_key_file")) {
			config.tls.private_key_file =
				requiredString(*tls, "private_key_file", {}, "tls");
		}
	}
	if (const Json *logging = optionalObject(document, "logging")) {
		rejectUnknownKeys(*logging, {"sink", "path", "level"},
						  "Runtime config logging");
		config.logging.sink =
			requiredString(*logging, "sink", config.logging.sink, "logging");
		config.logging.path =
			requiredString(*logging, "path", config.logging.path, "logging");
		config.logging.level =
			requiredString(*logging, "level", config.logging.level, "logging");
	}
	if (const Json *limits = optionalObject(document, "rate_limits")) {
		rejectUnknownKeys(*limits,
						  {"failed_auth_attempts", "failed_auth_window_seconds",
						   "api_requests_per_minute",
						   "firewall_mutations_per_minute"},
						  "Runtime config rate_limits");
		config.rate_limits.failed_auth_attempts = boundedInteger(
			*limits, "failed_auth_attempts",
			config.rate_limits.failed_auth_attempts, Limits::MIN_RATE_LIMIT,
			Limits::MAX_RATE_LIMIT, "rate_limits");
		config.rate_limits.failed_auth_window_seconds =
			boundedInteger(*limits, "failed_auth_window_seconds",
						   config.rate_limits.failed_auth_window_seconds,
						   Limits::MIN_RATE_LIMIT,
						   Limits::MAX_SESSION_LIFETIME_SECONDS, "rate_limits");
		config.rate_limits.api_requests_per_minute = boundedInteger(
			*limits, "api_requests_per_minute",
			config.rate_limits.api_requests_per_minute, Limits::MIN_RATE_LIMIT,
			Limits::MAX_RATE_LIMIT, "rate_limits");
		config.rate_limits.firewall_mutations_per_minute = boundedInteger(
			*limits, "firewall_mutations_per_minute",
			config.rate_limits.firewall_mutations_per_minute,
			Limits::MIN_RATE_LIMIT, Limits::MAX_RATE_LIMIT, "rate_limits");
	}
	validateAppConfig(config);
	return config;
}

std::string generateRuntimeConfig(const AppConfig &config) {
	validateAppConfig(config);

	Json document = {
		{	 "format","archangel-runtime-config"						 },
		{	 "version",										1},
		{	 "server",
		 {{"bind_address", config.server.bind_address},
		  {"port", config.server.port}}						   },
		{		 "auth",
		 {{"provider", config.auth.provider},
		  {"database_path", config.auth.database_path},
		  {"password_min_length", config.auth.password_min_length},
		  {"password_max_length", config.auth.password_max_length},
		  {"argon2id",
		   {{"memory_kib", config.auth.argon2id_memory_kib},
			{"iterations", config.auth.argon2id_iterations},
			{"parallelism", config.auth.argon2id_parallelism}}}}	},
		{	 "sessions",
		 {{"idle_timeout_seconds", config.sessions.idle_timeout_seconds},
		  {"absolute_timeout_seconds",
		   config.sessions.absolute_timeout_seconds}}			 },
		{		 "tls",		{{"enabled", config.tls.enabled}}},
		{	 "logging",
		 {{"sink", config.logging.sink},
		  {"path", config.logging.path},
		  {"level", config.logging.level}}						  },
		{"rate_limits",
		 {{"failed_auth_attempts", config.rate_limits.failed_auth_attempts},
		  {"failed_auth_window_seconds",
		   config.rate_limits.failed_auth_window_seconds},
		  {"api_requests_per_minute",
		   config.rate_limits.api_requests_per_minute},
		  {"firewall_mutations_per_minute",
		   config.rate_limits.firewall_mutations_per_minute}}	 }
	  };
	if (!config.auth.password_blocklist_path.empty()) {
		document["auth"]["password_blocklist_path"] =
			config.auth.password_blocklist_path;
	}
	if (!config.tls.certificate_file.empty()) {
		document["tls"]["certificate_file"] = config.tls.certificate_file;
	}
	if (!config.tls.private_key_file.empty()) {
		document["tls"]["private_key_file"] = config.tls.private_key_file;
	}
	return document.dump(2) + "\n";
}

void writeRuntimeConfig(const std::string &path, const AppConfig &config) {
	if (path.empty()) {
		throw std::runtime_error("Runtime config destination path is empty");
	}
	const std::string			content = generateRuntimeConfig(config);
	const std::filesystem::path destination(path);
	const std::filesystem::path parent = destination.has_parent_path()
											 ? destination.parent_path()
											 : std::filesystem::path(".");
	std::filesystem::perms		directoryPermissions =
		std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
		std::filesystem::perms::group_exec |
		std::filesystem::perms::others_read |
		std::filesystem::perms::others_exec;
#ifdef ARCHANGEL_DEV_BUILD
	if (path == Defaults::configPath()) {
		directoryPermissions = std::filesystem::perms::owner_all;
	}
#endif
	const mode_t	previousMask = umask(0077);
	std::error_code directoryError;
	const bool		parentCreated =
		std::filesystem::create_directories(parent, directoryError);
	umask(previousMask);
	if (directoryError) {
		throw std::runtime_error(
			"Unable to create runtime config directory: " + parent.string() +
			": " + directoryError.message());
	}
	if (parentCreated &&
		chmod(parent.c_str(), static_cast<mode_t>(directoryPermissions)) != 0) {
		throw std::runtime_error("Unable to set runtime config directory "
								 "permissions: " +
								 parent.string());
	}

	const int file =
		open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
			 0644);
	if (file == -1) {
		if (errno == EEXIST) {
			throw std::runtime_error("Runtime config already exists: " + path);
		}
		throw std::runtime_error("Unable to create runtime config: " + path);
	}

	std::string failure;
	std::size_t offset = 0;
	while (offset < content.size()) {
		const ssize_t count =
			write(file, content.data() + offset, content.size() - offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			failure = "Unable to write runtime config: " + path;
			break;
		}
		offset += static_cast<std::size_t>(count);
	}
	if (failure.empty() && fchmod(file, 0644) != 0) {
		failure = "Unable to set runtime config permissions: " + path;
	}
	if (failure.empty() && fsync(file) != 0) {
		failure = "Unable to sync runtime config: " + path;
	}
	if (close(file) != 0 && failure.empty()) {
		failure = "Unable to close runtime config: " + path;
	}
	if (!failure.empty()) {
		unlink(path.c_str());
		throw std::runtime_error(failure);
	}
}

AppConfig loadRuntimeConfig(const std::string &path, bool allowMissing) {
	const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (file == -1) {
		if (allowMissing && errno == ENOENT) {
			return AppConfig{};
		}
		throw std::runtime_error("Unable to open runtime config: " + path);
	}

	struct stat info {};
	if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) ||
		(info.st_uid != 0 && info.st_uid != geteuid()) ||
		(info.st_mode & 0022) != 0) {
		close(file);
		throw std::runtime_error("Runtime config must be a regular file owned "
								 "by root or the service "
								 "user and not group/world writable");
	}
	if (info.st_size <= 0 || static_cast<std::uint64_t>(info.st_size) >
								 Limits::MAX_RUNTIME_CONFIG_BYTES) {
		close(file);
		throw std::runtime_error(
			"Runtime config must be between 1 byte and 1 MiB");
	}

	std::string content(static_cast<std::size_t>(info.st_size), '\0');
	std::size_t offset = 0;
	while (offset < content.size()) {
		const ssize_t count =
			read(file, content.data() + offset, content.size() - offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			close(file);
			throw std::runtime_error("Unable to read runtime config: " + path);
		}
		offset += static_cast<std::size_t>(count);
	}
	if (close(file) != 0) {
		throw std::runtime_error("Unable to close runtime config: " + path);
	}
	return parseRuntimeConfig(content);
}

} // namespace Config
