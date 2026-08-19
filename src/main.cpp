#include "../include/main.hpp"
#include "../include/logger.hpp"

int main(int argc, char *argv[]) {
	CLI::App app{"Archangel firewall"};
	
	app.add_option("--host", CLI_ARGS::http_hostname, "HTTP server address");
	app.add_option("--port", CLI_ARGS::http_port, "HTTP server port");
	
	CLI11_PARSE(app, argc, argv);
	
	Logger::Program::log("Starting program");

	try {
		Nftables nftables;

		HttpServer server(nftables);

		server.run();
	} catch (const std::exception &exception) {
		Logger::Program::log("Archangel error: " + std::string(exception.what()));

		return 1;
	}

	return 0;
}
