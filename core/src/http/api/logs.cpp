#include "http/api/logs.hpp"
#include "json/json.hpp"

namespace Http {

void getLogs(const std::vector<std::unique_ptr<Logs::LogSource>> &sources,
			 const httplib::Request &, httplib::Response &response) {
	nlohmann::json results = nlohmann::json::array();
	for (const Logs::LogSourceResult &source : Logs::readLogSources(sources)) {
		results.push_back({
			{		 "id",		   source.id},
			{	 "label",	  source.label},
			{"available", source.available},
			{	 "detail",	   source.detail},
			{	 "entries",	source.entries},
		});
	}
	response.set_content(
		nlohmann::json{
			{"sources", std::move(results)}
	   }
			.dump(),
		"application/json");
}

} // namespace Http
