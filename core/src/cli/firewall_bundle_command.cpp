#include "cli/firewall_bundle_command.hpp"
#include "config/app_config.hpp"
#include "firewall/bundle.hpp"

#include <fstream>
#include <stdexcept>

namespace Cli {

namespace {}

Firewall::BundleProvider &requireBundleProvider(Firewall::Backend &firewall) {
	auto *provider = dynamic_cast<Firewall::BundleProvider *>(&firewall);
	if (provider == nullptr) {
		throw std::runtime_error(
			"The selected firewall backend does not support config "
			"import/export");
	}
	return *provider;
}

std::string readBundle(const std::string &path) {
	std::ifstream input(path, std::ios::binary);
	if (!input) {
		throw std::runtime_error("Unable to open firewall config bundle: " +
								 path);
	}
	input.seekg(0, std::ios::end);
	const std::streamoff size = input.tellg();
	if (size <= 0 || size > Config::Limits::MAX_FIREWALL_BUNDLE_BYTES) {
		throw std::runtime_error(
			"Firewall config bundle must be between 1 byte and 16 MiB");
	}
	input.seekg(0, std::ios::beg);
	std::string content(static_cast<std::size_t>(size), '\0');
	if (!input.read(content.data(), size)) {
		throw std::runtime_error("Unable to read firewall config bundle: " +
								 path);
	}
	return content;
}

void writeBundle(const std::string &path, const std::string &ruleset) {
	const std::string configuration = Firewall::serializeBundle(ruleset);
	if (configuration.size() >
		static_cast<std::size_t>(Config::Limits::MAX_FIREWALL_BUNDLE_BYTES)) {
		throw std::runtime_error(
			"Exported firewall config exceeds the 16 MiB limit");
	}
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	if (!output ||
		!output.write(configuration.data(),
					  static_cast<std::streamsize>(configuration.size()))) {
		throw std::runtime_error("Unable to write exported firewall config: " +
								 path);
	}
	output.flush();
	if (!output) {
		throw std::runtime_error("Unable to finish writing firewall config: " +
								 path);
	}
}

} // namespace Cli
