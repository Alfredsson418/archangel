#include "../../../include/http/api/logs.hpp"
#include "../../../include/logger.hpp"
#include "../../../lib/json/json.hpp"
#include "../../logs/log_sources.hpp"

namespace HttpApi {

void getLogs(Firewall &firewall, const httplib::Request &,
			 httplib::Response &response) {
	const BackendLogSources::ReadResult result =
		BackendLogSources::readSources(firewall);
	if (result.rulesetUnavailable) {
		Logger::API::log("log_source_unavailable source=nftables",
						 Logger::Level::WARNING);
	}

	nlohmann::json sources = nlohmann::json::array();
	for (const BackendLogSources::Source &source : result.sources) {
		sources.push_back({
			{"id", source.id},
			{"label", source.label},
			{"available", source.available},
			{"detail", source.detail},
			{"entries", source.entries},
		});
	}
	response.set_content(
		nlohmann::json{{"sources", std::move(sources)}}.dump(),
		"application/json");
}

} // namespace HttpApi
