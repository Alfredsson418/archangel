#pragma once

#include "../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../cli.hpp"
#include "../firewall/nft.hpp"
#include <iostream>
#include <string>

class Nftables;

class HttpServer {
  public:
	HttpServer(Nftables &nftables);

	void run();

  private:
	Nftables &nftables_;
};
