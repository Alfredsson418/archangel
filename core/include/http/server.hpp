#pragma once

#include "auth/providers/auth_provider.hpp"
#include "config/app_config.hpp"
#include "cpp-httplib/cpp-httplib.hpp"
#include "firewall/providers/firewall.hpp"
#include "http/authentication.hpp"
#include "logs/providers/log_source.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

class HttpServer {
  public:
	/**
	 * @brief Initializes the HTTP server with the supplied backend abstraction.
	 * @param firewall Backend used by API route handlers.
	 * @param auth Authentication provider for sessions and accounts.
	 * @param logSources Sources returned by GET /api/v1/logs, in order.
	 * @param serverConfig Effective bind address and port.
	 * @param tlsConfig Effective TLS settings; when enabled, the listener
	 * serves HTTPS only.
	 * @param rateLimits Effective request and login rate limits.
	 * @return No value.
	 */
	HttpServer(Firewall &firewall, Auth::AuthProvider &auth,
			   std::vector<std::unique_ptr<Logging::LogSource>> logSources,
			   AppConfig::Server serverConfig, AppConfig::Tls tlsConfig,
			   AppConfig::RateLimits rateLimits);

	/**
	 * @brief Registers API routes and serves requests on the configured
	 * address.
	 * @return No value; returns when serving stops.
	 * @throws std::runtime_error If the TLS setup is invalid or the server
	 * cannot start.
	 */
	void run();

  private:
	Firewall										&firewall_;
	Auth::AuthProvider								&auth_;
	std::vector<std::unique_ptr<Logging::LogSource>> log_sources_;
	HttpApi::RateLimiter							 login_limiter_;
	HttpApi::RateLimiter							 source_rate_limiter_;
	HttpApi::RateLimiter							 identity_rate_limiter_;
	HttpApi::RateLimiter				  firewall_mutation_source_limiter_;
	HttpApi::RateLimiter				  firewall_mutation_identity_limiter_;
	AppConfig::Server					  server_config_;
	AppConfig::Tls						  tls_config_;
	std::chrono::steady_clock::time_point started_at_;
};
