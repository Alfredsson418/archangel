#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {
void getSystemStatistics(const httplib::Request &request,
						 httplib::Response		&response);
}
