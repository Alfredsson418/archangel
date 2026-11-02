#include "config/app_config.hpp"
#include "http/request_audit.hpp"
#include "logs/logger.hpp"
#include "logs/providers/application_log_source.hpp"
#include "logs/providers/jsonl_file_sink.hpp"
#include "logs/providers/nftables_journal_source.hpp"
#include "test_support.hpp"

#include "json/json.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {
namespace fs = std::filesystem;

class CapturingSink final : public Logs::LogSink {
  public:
	bool write(const Logs::LogRecord &record) override {
		records.push_back(record);
		return !fail;
	}
	void reopen() override { ++reopens; }

	std::vector<Logs::LogRecord> records;
	bool						 fail	 = false;
	int							 reopens = 0;
};

class RulesetFirewall final : public Firewall::Backend {
  public:
	explicit RulesetFirewall(std::string ruleset)
		: ruleset_(std::move(ruleset)) {}
	std::string			 listRules() override { return ruleset_; }
	Firewall::Statistics getStatistics() override { return {}; }
	void				 addRule(const Firewall::RuleSpec &) override {}
	void				 deleteRule(const std::string &, const std::string &,
									const std::string &, std::uint64_t) override {}
	std::vector<Firewall::ChainRevision> chainRevisions() override {
		return {};
	}
	void checkChanges(const Firewall::ChangeSet &) override {}
	void applyChanges(const Firewall::ChangeSet &) override {}

  private:
	std::string ruleset_;
};

class FixedSource final : public Logs::LogSource {
  public:
	explicit FixedSource(std::vector<std::string> entries)
		: entries_(std::move(entries)) {}
	Logs::LogSourceResult read() override {
		return {"fixed", "Fixed", true, "Fixed entries.", entries_};
	}

  private:
	std::vector<std::string> entries_;
};

// Creates a private temporary directory removed when the guard is destroyed.
class TemporaryDirectory {
  public:
	TemporaryDirectory() {
		char pattern[] = "/tmp/archangel-logging-test-XXXXXX";
		if (mkdtemp(pattern) == nullptr) {
			throw std::runtime_error("Unable to create a temporary directory");
		}
		path = pattern;
	}
	~TemporaryDirectory() {
		std::error_code error;
		fs::remove_all(path, error);
	}
	fs::path path;
};

std::vector<nlohmann::json> readJsonLines(const fs::path &file) {
	std::ifstream				stream(file);
	std::vector<nlohmann::json> lines;
	std::string					line;
	while (std::getline(stream, line)) {
		lines.push_back(nlohmann::json::parse(line));
	}
	return lines;
}

Logs::LogRecord record(std::string						  event,
					   std::map<std::string, std::string> fields = {}) {
	return {std::chrono::system_clock::now(), "INFO", "API", std::move(event),
			std::move(fields)};
}

void writesOwnerOnlyJsonLines() {
	TemporaryDirectory directory;
	const fs::path	   file = directory.path / "logs" / "backend.jsonl";
	{
		Logs::JsonlFileSink sink(file.string(), "backend");
		TestSupport::require(
			sink.write(record(
				"rule_added",
				{
					{"family",			   "inet"},
					{ "level", "must not override"}
		  })),
			"the sink should report a successful write");
	}
	struct stat fileInfo {};
	struct stat directoryInfo {};
	stat(file.c_str(), &fileInfo);
	stat(file.parent_path().c_str(), &directoryInfo);
	TestSupport::require((fileInfo.st_mode & 0777) == 0600,
						 "the log file should be created with mode 0600");
	TestSupport::require((directoryInfo.st_mode & 0777) == 0700,
						 "a missing log directory should be created as 0700");
	const auto lines = readJsonLines(file);
	TestSupport::require(lines.size() == 1, "one record should be one line");
	TestSupport::require(
		lines[0]["service"] == "backend" && lines[0]["level"] == "INFO" &&
			lines[0]["category"] == "API" &&
			lines[0]["event"] == "rule_added" && lines[0]["family"] == "inet" &&
			lines[0]["timestamp"].get<std::string>().back() == 'Z',
		"records should carry the envelope and their fields, "
		"and fields must not override envelope keys");
}

void rejectsUnsafeLogPaths() {
	TemporaryDirectory directory;
	const fs::path	   target = directory.path / "target.jsonl";
	std::ofstream(target).close();
	chmod(target.c_str(), 0600);
	const fs::path link = directory.path / "link.jsonl";
	fs::create_symlink(target, link);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Logs::JsonlFileSink sink(link.string(), "backend"); },
		"a symlinked log path must be rejected");

	const fs::path shared = directory.path / "shared";
	fs::create_directory(shared);
	chmod(shared.c_str(), 0777);
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			Logs::JsonlFileSink sink((shared / "backend.jsonl").string(),
									 "backend");
		},
		"a group- or world-writable log directory must be rejected");

	const fs::path readable = directory.path / "readable.jsonl";
	std::ofstream(readable).close();
	chmod(readable.c_str(), 0644);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Logs::JsonlFileSink sink(readable.string(), "backend"); },
		"an existing log file readable by others must be rejected");
}

void reopensAfterRotation() {
	TemporaryDirectory	directory;
	const fs::path		file = directory.path / "backend.jsonl";
	Logs::JsonlFileSink sink(file.string(), "backend");
	sink.write(record("before_rotation"));
	fs::rename(file, directory.path / "backend.jsonl.1");
	sink.reopen();
	sink.write(record("after_rotation"));
	const auto rotated = readJsonLines(directory.path / "backend.jsonl.1");
	const auto current = readJsonLines(file);
	TestSupport::require(
		rotated.size() == 1 && rotated[0]["event"] == "before_rotation" &&
			current.size() == 1 && current[0]["event"] == "after_rotation",
		"reopen should continue in a new file after rename");
}

void structuresLegacyMessagesAndFiltersLevels() {
	const auto sink = std::make_shared<CapturingSink>();
	Logs::Logger::configure(sink, Logs::Logger::Level::INFO);
	Logs::Logger::API::log("request_rejected code=rate_limited",
						   Logs::Logger::Level::WARNING);
	Logs::Logger::Program::log("Starting program");
	Logs::Logger::Program::log("hidden detail", Logs::Logger::Level::DEBUG);
	TestSupport::require(sink->records.size() == 2,
						 "messages below the minimum level should be dropped");
	TestSupport::require(sink->records[0].event == "request_rejected" &&
							 sink->records[0].fields.at("code") ==
								 "rate_limited" &&
							 sink->records[0].level == "WARNING" &&
							 sink->records[0].category == "API",
						 "event key=value messages should become fields");
	TestSupport::require(sink->records[1].event == "message" &&
							 sink->records[1].fields.at("message") ==
								 "Starting program",
						 "other messages should be kept as a message field");

	Logs::Logger::configure(sink, Logs::Logger::Level::ERROR);
	TestSupport::require(Logs::Logger::audit(record("audit_event")) &&
							 sink->records.back().event == "audit_event",
						 "audit records should ignore the minimum level");

	Logs::Logger::requestReopen();
	Logs::Logger::Program::log("after_reopen", Logs::Logger::Level::ERROR);
	TestSupport::require(sink->reopens == 1,
						 "a requested reopen should happen before the next "
						 "write");
	TestSupport::requireThrows<std::invalid_argument>(
		[] { Logs::Logger::parseLevel("VERBOSE"); },
		"unknown log levels should be rejected");
	Logs::Logger::configure(nullptr, Logs::Logger::Level::INFO);
}

void auditsRequestsAndFailsClosed() {
	Http::RoutePolicies routes;
	routes.add("POST", "/api/v1/rules", {Http::RouteAccess::Operator, true});
	httplib::Request request;
	request.method		= "POST";
	request.path		= "/api/v1/rules";
	request.remote_addr = "192.0.2.80";
	httplib::Response  response;
	Http::RequestAudit audit =
		Http::beginRequestAudit(request, routes, response);
	audit.actorId = "operator-id";
	TestSupport::require(
		audit.requestId.size() == 32 &&
			response.get_header_value(Http::REQUEST_ID_HEADER) ==
				audit.requestId &&
			audit.operation == "POST /api/v1/rules",
		"requests should get a 128-bit ID returned in X-Request-ID");

	const auto sink = std::make_shared<CapturingSink>();
	Logs::Logger::configure(sink, Logs::Logger::Level::INFO);
	TestSupport::require(Http::recordAuthorizedRequest(audit, response) ==
							 httplib::Server::HandlerResponse::Unhandled,
						 "a recorded request should proceed");
	const auto &authorized = sink->records.back();
	TestSupport::require(
		authorized.event == "api_request_authorized" &&
			authorized.fields.at("actor_id") == "operator-id" &&
			authorized.fields.at("source_ip") == "192.0.2.80" &&
			authorized.fields.at("request_id") == audit.requestId,
		"the authorization record should identify the "
		"request, actor, operation, and source");

	response.status = 201;
	Http::recordCompletedRequest(audit, response);
	const auto &completed = sink->records.back();
	TestSupport::require(completed.event == "api_request_completed" &&
							 completed.fields.at("status") == "201" &&
							 completed.fields.at("outcome") == "success" &&
							 completed.fields.count("duration_ms") == 1,
						 "the completion record should carry the outcome");

	sink->fail = true;
	httplib::Response failed;
	TestSupport::require(
		Http::recordAuthorizedRequest(audit, failed) ==
				httplib::Server::HandlerResponse::Handled &&
			failed.status == 503 &&
			nlohmann::json::parse(failed.body)["code"] ==
				"audit_log_unavailable",
		"a protected request must not proceed when its audit record fails");

	httplib::Request unknown;
	unknown.method = "GET";
	unknown.path   = "/api/v1/private-token-in-path";
	TestSupport::require(
		Http::beginRequestAudit(unknown, routes, failed).operation ==
			"GET unregistered",
		"unregistered paths must not be recorded verbatim");
	Logs::Logger::configure(nullptr, Logs::Logger::Level::INFO);
}

void appliesSharedSourceBoundsAndRedaction() {
	std::vector<std::string> entries(Config::Limits::MAX_LOG_ENTRIES + 5,
									 "entry");
	entries[0] = "password=hunter2 token: \"abc\"";
	entries[1] = std::string(Config::Limits::MAX_LOG_LINE_BYTES + 10, 'x');
	std::vector<std::unique_ptr<Logs::LogSource>> sources;
	sources.push_back(std::make_unique<FixedSource>(entries));
	const auto results = Logs::readLogSources(sources);
	TestSupport::require(results.size() == 1 &&
							 results[0].entries.size() ==
								 Config::Limits::MAX_LOG_ENTRIES,
						 "entries should be limited per source");
	TestSupport::require(
		results[0].entries[0].find("hunter2") == std::string::npos &&
			results[0].entries[0].find("abc") == std::string::npos,
		"credential values should be redacted");
	TestSupport::require(results[0].entries[1].size() ==
							 Config::Limits::MAX_LOG_LINE_BYTES,
						 "long entries should be truncated");
}

void readsTheApplicationLog() {
	TemporaryDirectory directory;
	const fs::path	   file = directory.path / "backend.jsonl";
	{
		Logs::JsonlFileSink sink(file.string(), "backend");
		sink.write(record("first_event", {
											 {"status", "200"}
		  }));
		sink.write(record("message", {
										 {"message", "Starting program"}
		}));
	}
	std::vector<std::unique_ptr<Logs::LogSource>> sources;
	sources.push_back(
		std::make_unique<Logs::ApplicationLogSource>(file.string()));
	sources.push_back(std::make_unique<Logs::ApplicationLogSource>(
		(directory.path / "missing.jsonl").string()));
	const auto results = Logs::readLogSources(sources);
	TestSupport::require(
		results[0].available && results[0].entries.size() == 2 &&
			results[0].entries[0].find("Starting program") !=
				std::string::npos &&
			results[0].entries[1].find("first_event status=200") !=
				std::string::npos,
		"JSONL records should be rendered newest first");
	TestSupport::require(!results[1].available && results[1].entries.empty(),
						 "a missing log file should be reported unavailable");
}

void reportsNftablesSourceState() {
	RulesetFirewall withoutLogging(
		R"({"nftables":[{"rule":{"expr":[{"accept":null}]}}]})");
	TestSupport::require(
		!Logs::NftablesJournalSource(withoutLogging).read().available,
		"the journal source should be unavailable without log statements");
	RulesetFirewall broken("not json");
	const auto		result = Logs::NftablesJournalSource(broken).read();
	TestSupport::require(!result.available &&
							 result.detail.find("could not be inspected") !=
								 std::string::npos,
						 "an unreadable ruleset should be reported safely");
}
} // namespace

void runLoggingTests() {
	writesOwnerOnlyJsonLines();
	rejectsUnsafeLogPaths();
	reopensAfterRotation();
	structuresLegacyMessagesAndFiltersLevels();
	auditsRequestsAndFailsClosed();
	appliesSharedSourceBoundsAndRedaction();
	readsTheApplicationLog();
	reportsNftablesSourceState();
}
