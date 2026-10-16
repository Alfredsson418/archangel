#include "../../../include/http/api/status.hpp"
#include "../../../include/http/api/schema.hpp"
#include "../../../lib/json/json.hpp"

namespace HttpApi {

void getStatus(const httplib::Request &, httplib::Response &response,
			   const std::string &backendVersion, std::uint64_t uptimeSeconds) {
	response.set_content(
		nlohmann::json{
			{		  "status",			  "ok"},
			{"backend_version", backendVersion},
			{	 "api_version",			  "v1"},
			{ "schema_version", SCHEMA_VERSION},
			{ "uptime_seconds",	 uptimeSeconds},
	}
			.dump(),
		"application/json");
}

} // namespace HttpApi
