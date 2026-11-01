#pragma once

#include <stdexcept>
#include <string>

namespace TestSupport {
inline void require(bool condition, const std::string &message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

template <typename Exception, typename Function>
void requireThrows(Function &&function, const std::string &message) {
	try {
		function();
	} catch (const Exception &) {
		return;
	}
	throw std::runtime_error(message);
}
} // namespace TestSupport
