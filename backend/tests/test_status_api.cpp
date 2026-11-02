#include "http/api/schema.hpp"
#include "http/api/status.hpp"
#include "test_support.hpp"
#include "json/json.hpp"

namespace {
void reportsTheConnectionAsTheBackendSeesIt() {
	httplib::Request request;
	request.remote_addr = "192.0.2.20";
	request.local_port	= 8443;
	httplib::Response response;

	Http::getStatus(request, response, "test-commit", 120);

	const auto body = nlohmann::json::parse(response.body);
	TestSupport::require(body["client_address"] == "192.0.2.20",
						 "status should report the caller's address");
	TestSupport::require(body["api_port"] == 8443,
						 "status should report the listening port");
	TestSupport::require(body["schema_version"] == Http::SCHEMA_VERSION,
						 "status should report the schema version");
	TestSupport::require(body["backend_version"] == "test-commit" &&
							 body["uptime_seconds"] == 120,
						 "status should keep its existing fields");
}
} // namespace

void runStatusApiTests() { reportsTheConnectionAsTheBackendSeesIt(); }
