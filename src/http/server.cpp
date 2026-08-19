#include "../../include/http/server.hpp"
#include "../../include/logger.hpp"
#include <string>

HttpServer::HttpServer(Nftables &nftables)
	: nftables_(nftables) {}

void HttpServer::run() {
	httplib::Server server;

	server.Get("/", [](const httplib::Request &, httplib::Response &response) {
		response.set_content("Archangel firewall\n", "text/plain");
	});

	server.Get("/api/v1/rules",
			   [this](const httplib::Request &, httplib::Response &response) {
				   try {
					   const std::string rules = nftables_.listRules();

					   response.set_content(rules, "application/json");
				   } catch (const std::exception &exception) {
					   std::cerr << "Failed to retrieve nftables rules: "
								 << exception.what() << '\n';

					   response.status = 500;

					   response.set_content(
						   "{\"error\":\"Failed to retrieve nftables rules\"}",
						   "application/json");
				   }
			   });

	Logger::Firewall::log("Archangel listening on " + CLI_ARGS::http_hostname + ":" + std::to_string(CLI_ARGS::http_port));

	if (!server.listen(CLI_ARGS::http_hostname.c_str(), CLI_ARGS::http_port)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
