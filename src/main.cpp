#include "../include/firewall/nft.hpp"
#include "../include/http/server.hpp"

#include "../lib/CLI11/CLI11.hpp"

#include <iostream>
#include <string>

struct arg_lit *help;
struct arg_str *host;
struct arg_int *port;
struct arg_end *end;

int main(int argc, char *argv[]) {

	CLI::App app{"Archangel firewall"};

	std::string host = "127.0.0.1";
	int			port = 8080;

	app.add_option("--host", host, "HTTP server address");
	app.add_option("--port", port, "HTTP server port");

	CLI11_PARSE(app, argc, argv);

	try {
		Nftables nftables;

		HttpServer server(nftables, host, port);

		server.run();
	} catch (const std::exception &exception) {
		std::cerr << "Archangel error: " << exception.what() << '\n';

		return 1;
	}

	return 0;
}
