#pragma once

#include <string>

class Nftables;

class HttpServer {
  public:
	HttpServer(Nftables &nftables, const std::string &host, int port);

	void run();

  private:
	Nftables   &nftables_;
	std::string host_;
	int			port_;
};
