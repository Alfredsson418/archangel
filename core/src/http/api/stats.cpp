#include "../../../include/http/api/stats.hpp"
#include "api_common.hpp"

namespace HttpApi {

void getStatistics(Firewall			 &firewall, const httplib::Request &,
				   httplib::Response &response) {
	Logger::API::log("GET /api/v1/stats");
	try {
		const FirewallStatistics statistics = firewall.getStatistics();
		const Detail::Json		 payload{
			{	   "total_rules",		statistics.total_rules},
			{	  "total_tables",	   statistics.total_tables},
			{	  "total_chains",	   statistics.total_chains},
			{  "rules_by_family",	statistics.rules_by_family},
			{"rules_by_protocol", statistics.rules_by_protocol},
			{ "rules_by_verdict",  statistics.rules_by_verdict},
		};
		response.set_content(payload.dump(), "application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "GET /api/v1/stats", error,
								   "firewall_error",
								   "Firewall operation failed");
	}
}

} // namespace HttpApi
