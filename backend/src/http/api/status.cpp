#include "http/api/status.hpp"
#include "http/api/schema.hpp"
#include "json/json.hpp"

namespace Http {

void getStatus(const httplib::Request &request, httplib::Response &response,
			   const std::string &backendVersion, std::uint64_t uptimeSeconds) {
	response.set_content(
		nlohmann::json{
			{		 "status",				   "ok"},
			{"backend_version",		backendVersion},
			{	 "api_version",				"v1"},
			{ "schema_version",	   SCHEMA_VERSION},
			{ "uptime_seconds",	   uptimeSeconds},
			// As the backend sees them, which is what its firewall matches.
			{ "client_address", request.remote_addr},
			{		 "api_port",	 request.local_port},
	}
			.dump(),
		"application/json");
}

} // namespace Http
