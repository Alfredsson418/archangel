#pragma once

#include "../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../cli.hpp"
#include "../firewall/firewall.hpp"
#include <iostream>
#include <string>

class HttpServer {
  public:
	HttpServer(Firewall &firewall);

	void run();

  private:
	Firewall &firewall_;
};
