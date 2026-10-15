#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"
#include "../../firewall/firewall.hpp"

namespace HttpApi {
void getRules(Firewall &firewall, const httplib::Request &request,
			  httplib::Response &response);
void createRule(Firewall &firewall, const httplib::Request &request,
				httplib::Response &response);
void deleteRule(Firewall &firewall, const httplib::Request &request,
				httplib::Response &response);
} // namespace HttpApi
