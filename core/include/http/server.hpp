#pragma once

#include "../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../config/app_config.hpp"
#include "../firewall/providers/firewall.hpp"
#include "authentication.hpp"
#include "../auth/providers/auth_provider.hpp"
#include <chrono>
#include <iostream>
#include <string>

class HttpServer {
  public:
	/**
	 * @brief Initializes the HTTP server with the supplied backend abstraction.
	 * @param firewall Backend used by API route handlers.
	 * @param serverConfig Effective bind address and port.
	 * @return No value.
	 */
	HttpServer(Firewall &firewall, Auth::AuthProvider &auth,
			   AppConfig::Server serverConfig,
			   AppConfig::RateLimits rateLimits);

	/**
	 * @brief Registers API routes and serves requests on the configured
	 * address.
	 * @return No value; returns when serving stops.
	 * @throws std::runtime_error If the HTTP server cannot start.
	 */
	void run();

  private:
	Firewall							 &firewall_;
	Auth::AuthProvider					 &auth_;
	HttpApi::LoginAttemptLimiter			  login_limiter_;
	AppConfig::Server					  server_config_;
	std::chrono::steady_clock::time_point started_at_;
};
