#include "../include/main.hpp"
#include "../include/logger.hpp"
#include "../lib/json/json.hpp"
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>

namespace {
constexpr std::streamoff MAX_CONFIG_BYTES = 16 * 1024 * 1024;
using Json = nlohmann::json;

std::string readConfiguration(const std::string &path) {
	std::ifstream input(path, std::ios::binary);
	if (!input) {
		throw std::runtime_error("Unable to open import configuration: " + path);
	}
	input.seekg(0, std::ios::end);
	const std::streamoff size = input.tellg();
	if (size <= 0 || size > MAX_CONFIG_BYTES) {
		throw std::runtime_error(
			"Import configuration must be between 1 byte and 16 MiB");
	}
	input.seekg(0, std::ios::beg);
	std::string content(static_cast<std::size_t>(size), '\0');
	if (!input.read(content.data(), size)) {
		throw std::runtime_error("Unable to read import configuration: " + path);
	}
	return content;
}

struct BackendConfig {
	std::string interface;
	unsigned short port;
	Json ruleset;
};

BackendConfig parseConfiguration(const std::string &content) {
	Json document;
	try {
		document = Json::parse(content);
	} catch (const Json::exception &error) {
		throw std::runtime_error(std::string("Invalid JSON config: ") +
								 error.what());
	}
	if (!document.is_object() || !document.contains("format") ||
		!document["format"].is_string() ||
		document["format"] != "archangel-backend-config" ||
		!document.contains("version") ||
		!document["version"].is_number_integer() ||
		document["version"] != 1 ||
		!document.contains("server") || !document["server"].is_object() ||
		!document.contains("firewall") || !document["firewall"].is_object() ||
		document.size() != 4) {
		throw std::runtime_error(
			"Config must use format archangel-backend-config version 1");
	}

	const Json &server = document["server"];
	if (!server.contains("interface") || !server["interface"].is_string() ||
		!server.contains("port") || !server["port"].is_number_integer() ||
		server.size() != 2) {
		throw std::runtime_error(
			"Config server requires a string interface and integer port");
	}
	const std::string interface = server["interface"].get<std::string>();
	const Json &port = server["port"];
	if (port < 1 || port > 65535) {
		throw std::runtime_error("Config server interface or port is invalid");
	}
	const auto portValue = port.get<unsigned int>();
	if (interface.empty() || interface.size() > 255 ||
		interface.find_first_of(" \t\r\n") != std::string::npos ||
		interface.find('\0') != std::string::npos) {
		throw std::runtime_error("Config server interface or port is invalid");
	}

	const Json &firewall = document["firewall"];
	if (!firewall.contains("ruleset") || !firewall["ruleset"].is_object() ||
		!firewall["ruleset"].contains("nftables") ||
		!firewall["ruleset"]["nftables"].is_array() ||
		firewall.size() != 1 ||
		firewall["ruleset"].size() != 1) {
		throw std::runtime_error(
			"Config firewall.ruleset must contain an nftables array");
	}
	return {interface, static_cast<unsigned short>(portValue),
			firewall["ruleset"]};
}

void writeConfiguration(const std::string &path, const std::string &interface,
						unsigned short port, const std::string &ruleset) {
	if (ruleset.size() > static_cast<std::size_t>(MAX_CONFIG_BYTES)) {
		throw std::runtime_error(
			"Exported nftables ruleset exceeds the 16 MiB config limit");
	}
	Json document{
		{"format", "archangel-backend-config"},
		{"version", 1},
		{"server", {{"interface", interface}, {"port", port}}},
		{"firewall", {{"ruleset", Json::parse(ruleset)}}},
	};
	const std::string configuration = document.dump(2) + "\n";
	if (configuration.size() > static_cast<std::size_t>(MAX_CONFIG_BYTES)) {
		throw std::runtime_error(
			"Exported config exceeds the 16 MiB config limit");
	}
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	if (!output || !output.write(configuration.data(),
								 static_cast<std::streamsize>(configuration.size()))) {
		throw std::runtime_error("Unable to write exported configuration: " + path);
	}
	output.flush();
	if (!output) {
		throw std::runtime_error("Unable to finish writing configuration: " + path);
	}
}
} // namespace

/**
 * @brief Parses runtime options and starts the firewall API service.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument strings.
 * @return 0 on normal shutdown; 1 if startup or runtime fails.
 */
int main(int argc, char *argv[]) {
	CLI::App app{"Archangel firewall"};

	auto *hostOption =
		app.add_option("--host", CLI_ARGS::http_hostname,
					   "HTTP server bind address (overrides imported config)");
	auto *portOption =
		app.add_option("--port", CLI_ARGS::http_port,
					   "HTTP server port (overrides imported config)");
	app.add_option("--import-config", CLI_ARGS::import_config_path,
				   "Import a versioned Archangel JSON config before serving");
	app.add_option("--export-config", CLI_ARGS::export_config_path,
				   "Export bind settings and the complete nftables ruleset as JSON");
	std::string rulesMode;
	auto *rulesModeOption =
		app.add_option("--rules-mode", rulesMode,
					   "Required with --import-config: merge or replace");

	CLI11_PARSE(app, argc, argv);

	if (!CLI_ARGS::import_config_path.empty() &&
		!CLI_ARGS::export_config_path.empty()) {
		std::cerr << "--import-config and --export-config cannot be used together\n";
		return 2;
	}
	if (!CLI_ARGS::import_config_path.empty() && rulesModeOption->count() == 0) {
		std::cerr << "--rules-mode merge|replace is required with --import-config\n";
		return 2;
	}
	if (CLI_ARGS::import_config_path.empty() && rulesModeOption->count() > 0) {
		std::cerr << "--rules-mode can only be used with --import-config\n";
		return 2;
	}
	if (!CLI_ARGS::import_config_path.empty() && rulesMode != "merge" &&
		rulesMode != "replace") {
		std::cerr << "--rules-mode must be merge or replace\n";
		return 2;
	}
	if (CLI_ARGS::http_port == 0) {
		std::cerr << "--port must be between 1 and 65535\n";
		return 2;
	}

	Logger::Program::log("Starting program");

	try {
		if (!CLI_ARGS::import_config_path.empty()) {
			const BackendConfig config =
				parseConfiguration(readConfiguration(CLI_ARGS::import_config_path));
			if (hostOption->count() == 0) {
				CLI_ARGS::http_hostname = config.interface;
			}
			if (portOption->count() == 0) {
				CLI_ARGS::http_port = config.port;
			}
			Nftables nftables;
			nftables.importRuleset(config.ruleset.dump(), rulesMode == "replace");
			Logger::Program::log("Imported Archangel JSON configuration");
			HttpServer server(nftables);
			server.run();
			Logger::Program::log("Program stopped");
			return 0;
		}

		Nftables nftables;

		if (!CLI_ARGS::export_config_path.empty()) {
			writeConfiguration(CLI_ARGS::export_config_path,
							   CLI_ARGS::http_hostname, CLI_ARGS::http_port,
							   nftables.exportRuleset());
			Logger::Program::log("Exported Archangel JSON configuration");
			return 0;
		}

		HttpServer server(nftables);

		server.run();
		Logger::Program::log("Program stopped");
	} catch (const std::exception &exception) {
		Logger::Program::log("Archangel error: " +
							 std::string(exception.what()));

		return 1;
	}

	return 0;
}
