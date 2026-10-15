#include "../../../include/http/api/health.hpp"

namespace HttpApi {

void getHealth(const httplib::Request &, httplib::Response &response) {
	response.set_content("Archangel firewall\n", "text/plain");
}

} // namespace HttpApi
