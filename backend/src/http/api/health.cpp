#include "http/api/health.hpp"

namespace Http {

void getHealth(const httplib::Request &, httplib::Response &response) {
	response.status = 200;
}

} // namespace Http
