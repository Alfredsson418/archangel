#include "config/runtime_config.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
class TemporaryDirectory {
  public:
	TemporaryDirectory() {
		std::string		  pattern = "/tmp/archangel-runtime-config-XXXXXX";
		std::vector<char> writable(pattern.begin(), pattern.end());
		writable.push_back('\0');
		const char *created = mkdtemp(writable.data());
		if (created == nullptr) {
			throw std::runtime_error(
				"Unable to create runtime-config test directory");
		}
		path_ = created;
		chmod(path_.c_str(), 0700);
	}

	~TemporaryDirectory() {
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	const std::filesystem::path &path() const { return path_; }

  private:
	std::filesystem::path path_;
};

const std::string DEFAULT_CONFIG =
	R"({"format":"archangel-runtime-config","version":1})";

void parsesDefaultsAndOverrides() {
	const AppConfig defaults = parseRuntimeConfig(DEFAULT_CONFIG);
	TestSupport::require(defaults.server.bind_address == "localhost" &&
							 defaults.server.port == 8080,
						 "runtime config should provide server defaults");
	TestSupport::require(defaults.auth.database_path ==
								 AppConfigDefaults::AUTH_DATABASE_PATH &&
							 defaults.auth.argon2id_memory_kib == 19 * 1024 &&
							 defaults.auth.password_blocklist_path.empty(),
						 "runtime config should provide local-auth defaults");
	TestSupport::require(defaults.sessions.idle_timeout_seconds == 900 &&
							 defaults.sessions.absolute_timeout_seconds ==
								 28800,
						 "runtime config should provide session defaults");
	TestSupport::require(
		!defaults.tls.enabled &&
			defaults.logging.path == AppConfigDefaults::LOG_PATH &&
			defaults.rate_limits.api_requests_per_minute == 120,
		"application defaults should be centralized");

	const AppConfig config = parseRuntimeConfig(R"({
		"format":"archangel-runtime-config",
		"version":1,
		"server":{"bind_address":"127.0.0.1","port":9443},
		"auth":{
			"database_path":"/tmp/auth.db",
			"password_min_length":18,
			"password_blocklist_path":"/etc/archangel/blocked-passwords.txt",
			"argon2id":{"memory_kib":20480,"iterations":3}
		},
		"sessions":{"idle_timeout_seconds":600,"absolute_timeout_seconds":7200},
		"tls":{"enabled":true,"certificate_file":"/etc/archangel/cert.pem",
			"private_key_file":"/etc/archangel/key.pem"},
		"logging":{"path":"/var/log/archangel/custom.jsonl","level":"WARNING"},
		"rate_limits":{"api_requests_per_minute":60}
	})");
	TestSupport::require(config.server.bind_address == "127.0.0.1" &&
							 config.server.port == 9443,
						 "server config overrides should be retained");
	TestSupport::require(config.auth.database_path == "/tmp/auth.db" &&
							 config.auth.password_min_length == 18 &&
							 config.auth.password_max_length == 128 &&
							 config.auth.argon2id_iterations == 3 &&
							 config.auth.password_blocklist_path ==
								 "/etc/archangel/blocked-passwords.txt",
						 "auth settings should override only specified values");
	TestSupport::require(
		config.tls.enabled &&
			config.tls.private_key_file == "/etc/archangel/key.pem",
		"TLS settings should be parsed without embedding secrets");
	TestSupport::require(config.rate_limits.api_requests_per_minute == 60 &&
							 config.rate_limits.firewall_mutations_per_minute ==
								 30,
						 "rate-limit fields should default independently");
}

void validatesEffectiveCliOverrides() {
	AppConfig config;
	config.server.bind_address = "127.0.0.1";
	config.server.port		   = 9443;
	validateAppConfig(config);
	TestSupport::require(
		config.server.bind_address == "127.0.0.1" && config.server.port == 9443,
		"CLI overrides should be valid effective app settings");

	config.server.bind_address = "invalid address";
	TestSupport::requireThrows<std::runtime_error>(
		[&] { validateAppConfig(config); },
		"invalid CLI bind-address overrides should fail validation");
}

void generatesAndWritesRuntimeConfig() {
	AppConfig config;
	config.server.bind_address				   = "127.0.0.1";
	config.server.port						   = 9443;
	config.auth.database_path				   = "/tmp/generated-auth.db";
	config.auth.password_blocklist_path		   = "/etc/archangel/blocked.txt";
	config.tls.certificate_file				   = "/etc/archangel/cert.pem";
	config.tls.private_key_file				   = "/etc/archangel/key.pem";
	config.rate_limits.api_requests_per_minute = 60;

	const std::string generated = generateRuntimeConfig(config);
	const AppConfig	  parsed	= parseRuntimeConfig(generated);
	TestSupport::require(
		parsed.server.bind_address == config.server.bind_address &&
			parsed.server.port == config.server.port &&
			parsed.auth.database_path == config.auth.database_path &&
			parsed.auth.password_blocklist_path ==
				config.auth.password_blocklist_path &&
			parsed.tls.certificate_file == config.tls.certificate_file &&
			parsed.tls.private_key_file == config.tls.private_key_file &&
			parsed.rate_limits.api_requests_per_minute == 60,
		"generated runtime config should round-trip all supported settings");

	TemporaryDirectory directory;
	const auto		   path = directory.path() / "nested" / "config.json";
	writeRuntimeConfig(path.string(), config);
	struct stat info {};
	TestSupport::require(
		stat(path.c_str(), &info) == 0 && (info.st_mode & 0777) == 0644,
		"generated config should be readable but not writable by others");
	TestSupport::require(
		loadRuntimeConfig(path.string(), false).server.port == 9443,
		"generated config should be accepted by the runtime loader");
	TestSupport::requireThrows<std::runtime_error>(
		[&] { writeRuntimeConfig(path.string()); },
		"config generation must not overwrite an existing file");
}

void rejectsInvalidSchemaAndSecurityValues() {
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":2})");
		},
		"unsupported runtime-config versions must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":1,"server":{"extra":1}})");
		},
		"unknown keys must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":1,"tls":{"enabled":true}})");
		},
		"enabled TLS must require certificate and private-key paths");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":1,"auth":{"argon2id":{"memory_kib":1024}}})");
		},
		"Argon2id parameters must not lower the security baseline");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":1,"sessions":{"idle_timeout_seconds":500,"absolute_timeout_seconds":400}})");
		},
		"absolute session expiry must exceed idle expiry");
	TestSupport::requireThrows<std::runtime_error>(
		[] {
			parseRuntimeConfig(
				R"({"format":"archangel-runtime-config","version":1,"server":{"port":"8080"}})");
		},
		"wrongly typed settings must be rejected");
}

void loadsOnlyPrivateConfigFiles() {
	TemporaryDirectory directory;
	const auto		   path = directory.path() / "config.json";
	TestSupport::require(
		loadRuntimeConfig(path.string(), true).server.port == 8080,
		"an absent implicit config should return built-in defaults");
	TestSupport::requireThrows<std::runtime_error>(
		[&] { loadRuntimeConfig(path.string(), false); },
		"an absent explicit config must fail");

	{
		std::ofstream output(path);
		output << DEFAULT_CONFIG;
	}
	chmod(path.c_str(), 0600);
	TestSupport::require(loadRuntimeConfig(path.string(), false).server.port ==
							 8080,
						 "a private owner-controlled config should load");
	chmod(path.c_str(), 0664);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { loadRuntimeConfig(path.string(), false); },
		"group/world-writable config files must be rejected");

	chmod(path.c_str(), 0600);
	const auto link = directory.path() / "config-link.json";
	std::filesystem::create_symlink(path, link);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { loadRuntimeConfig(link.string(), false); },
		"runtime config symlinks must be rejected");
}
} // namespace

void runRuntimeConfigTests() {
	parsesDefaultsAndOverrides();
	validatesEffectiveCliOverrides();
	generatesAndWritesRuntimeConfig();
	rejectsInvalidSchemaAndSecurityValues();
	loadsOnlyPrivateConfigFiles();
}
