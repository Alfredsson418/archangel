#include "cli/firewall_bundle_command.hpp"
#include "firewall/bundle.hpp"
#include "test_support.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace {
class TestFirewall final : public Firewall {
  public:
	std::string		   listRules() override { return "{}"; }
	FirewallStatistics getStatistics() override { return {}; }
	void			   addRule(const RuleSpec &) override {}
	void			   deleteRule(const std::string &, const std::string &,
								  const std::string &, std::uint64_t) override {}
};

class TemporaryDirectory {
  public:
	TemporaryDirectory() {
		std::string		  pattern = "/tmp/archangel-firewall-config-XXXXXX";
		std::vector<char> writable(pattern.begin(), pattern.end());
		writable.push_back('\0');
		const char *created = mkdtemp(writable.data());
		if (created == nullptr) {
			throw std::runtime_error(
				"Unable to create firewall config test directory");
		}
		path_ = created;
	}

	~TemporaryDirectory() {
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	std::filesystem::path file(const std::string &name) const {
		return path_ / name;
	}

  private:
	std::filesystem::path path_;
};

void requiresAnImportExportCapableBackend() {
	TestFirewall firewall;
	TestSupport::requireThrows<std::runtime_error>(
		[&] { FirewallBundleCommand::requireProvider(firewall); },
		"unsupported firewall backends should fail explicitly");
}

void writesAndReadsVersionedBundles() {
	TemporaryDirectory directory;
	const auto		   path	   = directory.file("bundle.json");
	const std::string  ruleset = R"({"nftables":[]})";

	FirewallBundleCommand::writeBundle(path.string(), ruleset);
	const std::string bundle = FirewallBundleCommand::readBundle(path.string());
	const FirewallBundle parsed = parseFirewallBundle(bundle);
	TestSupport::require(parsed.ruleset == ruleset,
						 "written bundle should preserve its native ruleset");
}

void rejectsMissingAndEmptyBundleFiles() {
	TemporaryDirectory directory;
	const auto		   missing = directory.file("missing.json");
	TestSupport::requireThrows<std::runtime_error>(
		[&] { FirewallBundleCommand::readBundle(missing.string()); },
		"missing bundles should fail explicitly");

	const auto empty = directory.file("empty.json");
	std::ofstream(empty).close();
	TestSupport::requireThrows<std::runtime_error>(
		[&] { FirewallBundleCommand::readBundle(empty.string()); },
		"empty bundles should be rejected");
}
} // namespace

void runFirewallBundleCommandTests() {
	requiresAnImportExportCapableBackend();
	writesAndReadsVersionedBundles();
	rejectsMissingAndEmptyBundleFiles();
}
