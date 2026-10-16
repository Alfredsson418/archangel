#include "../../../include/http/api/health.hpp"

namespace HttpApi {

void getHealth(const httplib::Request &, httplib::Response &response) {
	response.status = 200;
}

} // namespace HttpApi
