#pragma once

#include "../../../lib/cpp-httplib/cpp-httplib.hpp"

namespace HttpApi {
void getHealth(const httplib::Request &request, httplib::Response &response);
}
