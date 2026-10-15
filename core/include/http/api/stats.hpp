#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../firewall/firewall.hpp"

namespace HttpApi {
void getStatistics(Firewall &firewall, const httplib::Request &request,
				   httplib::Response &response);
}
