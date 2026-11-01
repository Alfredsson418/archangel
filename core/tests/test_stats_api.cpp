#include "http/api/stats.hpp"
#include "test_support.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace {
class StatisticsFirewall final : public Firewall {
  public:
	std::string listRules() override { return R"({"nftables":[]})"; }

	FirewallStatistics getStatistics() override {
		FirewallStatistics statistics;
		statistics.total_rules	   = 3;
		statistics.total_tables	   = 2;
		statistics.total_chains	   = 4;
		statistics.rules_by_family = {
			{"inet", 2},
			 { "ip6", 1}
		   };
		statistics.rules_by_protocol = {
			{"tcp", 2},
			{"udp", 1}
		  };
		statistics.rules_by_verdict = {
			{"accept", 2},
			   {	"drop", 1}
		  };
		return statistics;
	}

	void addRule(const RuleSpec &) override {}

	void deleteRule(const std::string &, const std::string &,
					const std::string &, std::uint64_t) override {}
};

void serializesStatisticsResponse() {
	StatisticsFirewall firewall;
	httplib::Response  response;
	HttpApi::getStatistics(firewall, httplib::Request{}, response);

	TestSupport::require(response.body.find("\"total_rules\":3") !=
							 std::string::npos,
						 "statistics response should include total rules");
	TestSupport::require(response.body.find("\"total_tables\":2") !=
							 std::string::npos,
						 "statistics response should include total tables");
	TestSupport::require(response.body.find("\"total_chains\":4") !=
							 std::string::npos,
						 "statistics response should include total chains");
	TestSupport::require(
		response.body.find("\"rules_by_protocol\"") != std::string::npos,
		"statistics response should include protocol breakdown");
	TestSupport::require(
		response.body.find("\"rules_by_verdict\"") != std::string::npos,
		"statistics response should include verdict breakdown");
	TestSupport::require(response.get_header_value("Content-Type") ==
							 "application/json",
						 "statistics response should be JSON");
}
} // namespace

void runStatsApiTests() { serializesStatisticsResponse(); }
