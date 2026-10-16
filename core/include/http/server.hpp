#pragma once

#include "../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../cli.hpp"
#include "../firewall/firewall.hpp"
#include <iostream>
#include <string>

class HttpServer {
  public:
	/**
	 * @brief Initializes the HTTP server with the supplied backend abstraction.
	 * @param firewall Backend used by API route handlers.
	 */
	HttpServer(Firewall &firewall);

	/**
	 * @brief Registers API routes and serves requests on the configured
	 * address.
	 * @return No value; returns when serving stops.
	 * @throws std::runtime_error If the HTTP server cannot start.
	 */
	void run();

  private:
	Firewall &firewall_;
};
