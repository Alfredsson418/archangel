#include "../../include/http/server.hpp"
#include "../../include/firewall/nft.hpp"

#include "../../lib/cpp-httplib/cpp-httplib.hpp"

#include <iostream>

HttpServer::HttpServer(Nftables &nftables, const std::string &host, int port)
	: nftables_(nftables), host_(host), port_(port) {}

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

	std::cout << "Archangel listening on " << host_ << ':' << port_ << '\n';

	if (!server.listen(host_.c_str(), port_)) {
		throw std::runtime_error("Failed to start HTTP server");
	}
}
