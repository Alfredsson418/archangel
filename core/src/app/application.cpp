#include "app/application.hpp"
#include "auth/providers/sqlite_auth_provider.hpp"
#include "auth/secret_input.hpp"
#include "cli/firewall_config.hpp"
#include "config/runtime_config.hpp"
#include "firewall/config.hpp"
#include "firewall/providers/firewall_config_provider.hpp"
#include "firewall/providers/nft.hpp"
#include "http/server.hpp"
#include "logger.hpp"
#include "network/address.hpp"

#include "CLI11/CLI11.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

int runApplication(int argc, char *argv[]) {
	CLI::App app{"Archangel firewall"};
	auto *userCommand = app.add_subcommand("user", "Manage backend accounts");
	auto *bootstrapAdmin = userCommand->add_subcommand(
		"bootstrap-admin", "Create the initial administrator");
	std::string bootstrapUsername;
	std::string authDatabasePathOverride;
	bootstrapAdmin
		->add_option("--username", bootstrapUsername,
					 "Initial administrator username")
		->required();
	auto *databaseOption =
		bootstrapAdmin->add_option("--database", authDatabasePathOverride,
								   "Private authentication database path");
	userCommand->require_subcommand(1);

	auto *configCommand =
		app.add_subcommand("config", "Manage backend runtime config");
	auto *generateConfigCommand =
		configCommand->add_subcommand("generate", "Generate a default config");
	std::string generatedConfigPath;
	generateConfigCommand->add_option(
		"--output", generatedConfigPath,
		"Destination path (defaults to the runtime config path)");
	configCommand->require_subcommand(1);

	std::string runtimeConfigPath;
	auto	   *runtimeConfigOption = app.add_option(
		  "--config", runtimeConfigPath, "Backend runtime JSON config file");
	std::string hostOverride;
	int			portOverride = 0;
	auto	   *hostOption =
		app.add_option("--host", hostOverride,
					   "HTTP server bind address (overrides runtime config)");
	auto *portOption = app.add_option(
		"--port", portOverride, "HTTP server port (overrides runtime config)");
	std::string importFirewallConfigPath;
	std::string exportFirewallConfigPath;
	app.add_option("--import-firewall-config", importFirewallConfigPath,
				   "Import a versioned firewall ruleset bundle before serving");
	app.add_option("--export-firewall-config", exportFirewallConfigPath,
				   "Export the complete nftables ruleset as a firewall bundle");
	std::string rulesModeText;
	auto	   *rulesModeOption =
		app.add_option("--firewall-rules-mode", rulesModeText,
					   "Required with --import-firewall-config: merge, "
					   "replace, or replace-all");

	CLI11_PARSE(app, argc, argv);

	if (generateConfigCommand->parsed()) {
		if (runtimeConfigOption->count() > 0 || hostOption->count() > 0 ||
			portOption->count() > 0 || !importFirewallConfigPath.empty() ||
			!exportFirewallConfigPath.empty() || rulesModeOption->count() > 0) {
			std::cerr << "config generate cannot be combined with runtime "
						 "overrides or firewall bundle operations\n";
			return 2;
		}
		const std::string outputPath = generatedConfigPath.empty()
										   ? AppConfigDefaults::configPath()
										   : generatedConfigPath;
		try {
			writeRuntimeConfig(outputPath);
			std::cout << "Generated runtime config at " << outputPath << '\n';
			return 0;
		} catch (const std::exception &error) {
			std::cerr << "Runtime config generation failed: " << error.what()
					  << '\n';
			return 1;
		}
	}

	AppConfig appConfig;
	try {
		const bool explicitConfig = runtimeConfigOption->count() > 0;
		appConfig =
			loadRuntimeConfig(explicitConfig ? runtimeConfigPath
											 : AppConfigDefaults::configPath(),
							  !explicitConfig);
	} catch (const std::exception &error) {
		std::cerr << "Runtime configuration failed: " << error.what() << '\n';
		return 1;
	}

	if (userCommand->parsed()) {
		if (!bootstrapAdmin->parsed()) {
			std::cerr << "Unsupported user command\n";
			return 2;
		}
		try {
			if (databaseOption->count() > 0) {
				appConfig.auth.database_path = authDatabasePathOverride;
			}
			validateAppConfig(appConfig);
			Auth::SecretString password(
				Auth::promptPassword("New administrator password: "));
			Auth::SecretString confirmation(
				Auth::promptPassword("Confirm administrator password: "));
			if (password.value() != confirmation.value()) {
				std::cerr << "Passwords do not match\n";
				return 2;
			}
			Auth::SqliteAuthProvider provider(
				appConfig.auth.database_path,
				std::chrono::seconds(appConfig.sessions.idle_timeout_seconds),
				std::chrono::seconds(
					appConfig.sessions.absolute_timeout_seconds),
				Auth::PasswordPolicy{appConfig.auth.password_min_length,
									 appConfig.auth.password_max_length},
				Auth::Argon2idParameters{appConfig.auth.argon2id_memory_kib,
										 appConfig.auth.argon2id_iterations,
										 appConfig.auth.argon2id_parallelism});
			const Auth::Identity identity = provider.bootstrapAdministrator(
				bootstrapUsername, password.value());
			std::cout << "Created initial administrator account "
					  << identity.username << '\n';
			return 0;
		} catch (const std::exception &error) {
			std::cerr << "Account bootstrap failed: " << error.what() << '\n';
			return 1;
		}
	}

	if (hostOption->count() > 0) {
		appConfig.server.bind_address = hostOverride;
	}
	if (portOption->count() > 0) {
		if (portOverride < AppConfigLimits::MIN_SERVER_PORT ||
			portOverride > AppConfigLimits::MAX_SERVER_PORT) {
			std::cerr << "--port must be between "
					  << AppConfigLimits::MIN_SERVER_PORT << " and "
					  << AppConfigLimits::MAX_SERVER_PORT << '\n';
			return 2;
		}
		appConfig.server.port = static_cast<std::uint16_t>(portOverride);
	}
	try {
		validateAppConfig(appConfig);
	} catch (const std::exception &error) {
		std::cerr << "Effective application configuration is invalid: "
				  << error.what() << '\n';
		return 2;
	}
	if (appConfig.tls.enabled) {
		std::cerr << "Runtime TLS is configured but native TLS is not "
					 "implemented yet\n";
		return 1;
	}
	const AppConfig defaultAppConfig{};
	if (appConfig.logging.sink != defaultAppConfig.logging.sink ||
		appConfig.logging.path != defaultAppConfig.logging.path ||
		appConfig.logging.level != defaultAppConfig.logging.level) {
		std::cerr << "Custom runtime logging settings are not supported yet\n";
		return 1;
	}

	if (!importFirewallConfigPath.empty() &&
		!exportFirewallConfigPath.empty()) {
		std::cerr
			<< "--import-firewall-config and --export-firewall-config cannot "
			   "be used together\n";
		return 2;
	}
	if (!importFirewallConfigPath.empty() && rulesModeOption->count() == 0) {
		std::cerr << "--firewall-rules-mode merge|replace is required with "
					 "--import-firewall-config\n";
		return 2;
	}
	if (importFirewallConfigPath.empty() && rulesModeOption->count() > 0) {
		std::cerr << "--firewall-rules-mode can only be used with "
					 "--import-firewall-config\n";
		return 2;
	}
	if (!importFirewallConfigPath.empty() && rulesModeText != "merge" &&
		rulesModeText != "replace" && rulesModeText != "replace-all") {
		std::cerr << "--firewall-rules-mode must be merge, replace, or "
					 "replace-all\n";
		return 2;
	}
	if (!Network::isLoopbackAddress(appConfig.server.bind_address)) {
		Logger::Program::log(
			"SECURITY WARNING: API listener is non-loopback and TLS is not "
			"enabled; network traffic is unprotected",
			Logger::Level::WARNING);
	}
#ifdef ARCHANGEL_DEV_BUILD
	Logger::Program::log(
		"Development build: local-account passwords may be as short as " +
			std::to_string(AppConfigLimits::MIN_PASSWORD_LENGTH) +
			" characters; use a release build outside local testing",
		Logger::Level::WARNING);
#endif
	Logger::Program::log("Starting program");

	try {
		Nftables nftables;

		if (!exportFirewallConfigPath.empty()) {
			FirewallConfigProvider &configProvider =
				FirewallConfigCommand::requireProvider(nftables);
			FirewallConfigCommand::writeBundle(
				exportFirewallConfigPath,
				configProvider.exportFirewallConfig());
			Logger::Program::log("Exported Archangel firewall config bundle");
			return 0;
		}

		Auth::SqliteAuthProvider authProvider(
			appConfig.auth.database_path,
			std::chrono::seconds(appConfig.sessions.idle_timeout_seconds),
			std::chrono::seconds(appConfig.sessions.absolute_timeout_seconds),
			Auth::PasswordPolicy{appConfig.auth.password_min_length,
								 appConfig.auth.password_max_length},
			Auth::Argon2idParameters{appConfig.auth.argon2id_memory_kib,
									 appConfig.auth.argon2id_iterations,
									 appConfig.auth.argon2id_parallelism});

		if (!importFirewallConfigPath.empty()) {
			FirewallConfigProvider &configProvider =
				FirewallConfigCommand::requireProvider(nftables);
			const FirewallConfigImportMode importMode =
				resolveFirewallConfigImportMode(rulesModeText);
			configProvider.importFirewallConfig(
				FirewallConfigCommand::readBundle(importFirewallConfigPath),
				importMode);
			Logger::Program::log("Imported Archangel firewall config bundle");
			HttpServer server(nftables, authProvider, appConfig.server,
							  appConfig.rate_limits);
			server.run();
			Logger::Program::log("Program stopped");
			return 0;
		}

		HttpServer server(nftables, authProvider, appConfig.server,
						  appConfig.rate_limits);

		server.run();
		Logger::Program::log("Program stopped");
	} catch (const std::exception &exception) {
		Logger::Program::log("Archangel error: " +
							 std::string(exception.what()));

		return 1;
	}

	return 0;
}
