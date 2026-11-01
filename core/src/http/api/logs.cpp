#include "http/api/logs.hpp"
#include "json/json.hpp"

namespace HttpApi {

void getLogs(const std::vector<std::unique_ptr<Logging::LogSource>> &sources,
			 const httplib::Request &, httplib::Response &response) {
	nlohmann::json results = nlohmann::json::array();
	for (const Logging::LogSourceResult &source :
		 Logging::readLogSources(sources)) {
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

} // namespace HttpApi
