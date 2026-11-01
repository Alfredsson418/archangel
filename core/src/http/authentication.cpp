#include "../../include/http/authentication.hpp"
#include "../../include/http/api/schema.hpp"
#include "../../include/logger.hpp"
#include "../../lib/json/json.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <string>

namespace HttpApi {
namespace {
using Json = nlohmann::json;
constexpr std::size_t MAX_TRACKED_LOGIN_SOURCES = 4096;

void reject(httplib::Response &response, int status, const char *code,
			const char *message) {
	response.status = status;
	response.set_content(
		Json{{"error", message}, {"code", code}}.dump(),
		"application/json");
}

bool isPublicRoute(const httplib::Request &request) {
	return (request.method == "GET" && request.path == "/status/health") ||
		   (request.method == "POST" &&
			request.path == "/api/v1/auth/login");
}

bool requiresFirewallOperator(const httplib::Request &request) {
	return request.path == "/api/v1/rules" &&
		   (request.method == "POST" || request.method == "DELETE");
}
} // namespace

LoginAttemptLimiter::LoginAttemptLimiter(std::uint32_t maximumAttempts,
										 std::chrono::seconds window)
	: maximum_attempts_(maximumAttempts), window_(window) {
	if (maximum_attempts_ == 0 || window_ <= std::chrono::seconds::zero()) {
		throw std::invalid_argument("Login attempt limits must be positive");
	}
}

void LoginAttemptLimiter::pruneExpired(
	std::chrono::steady_clock::time_point now) {
	for (auto attempt = attempts_.begin(); attempt != attempts_.end();) {
		if (now - attempt->second.started >= window_) {
			attempt = attempts_.erase(attempt);
		} else {
			++attempt;
		}
	}
}

bool LoginAttemptLimiter::allow(std::string_view sourceAddress,
								std::uint32_t &retryAfterSeconds) {
	std::lock_guard<std::mutex> lock(mutex_);
	const auto now = std::chrono::steady_clock::now();
	pruneExpired(now);
	const std::string key =
		sourceAddress.empty() ? "<unknown>" : std::string(sourceAddress);
	auto attempt = attempts_.find(key);
	if (attempt == attempts_.end()) {
		if (attempts_.size() >= MAX_TRACKED_LOGIN_SOURCES) {
			retryAfterSeconds =
				static_cast<std::uint32_t>(window_.count());
			return false;
		}
		attempt = attempts_
					  .emplace(key, AttemptWindow{now, 0})
					  .first;
	}
	const auto elapsed =
		std::chrono::duration_cast<std::chrono::seconds>(
			now - attempt->second.started)
			.count();
	if (attempt->second.attempts >= maximum_attempts_) {
		retryAfterSeconds = static_cast<std::uint32_t>(
			std::max<std::int64_t>(1, window_.count() - elapsed));
		return false;
	}
	++attempt->second.attempts;
	retryAfterSeconds = 0;
	return true;
}

void LoginAttemptLimiter::clear(std::string_view sourceAddress) {
	std::lock_guard<std::mutex> lock(mutex_);
	const std::string key =
		sourceAddress.empty() ? "<unknown>" : std::string(sourceAddress);
	attempts_.erase(key);
}

std::optional<std::string> bearerToken(const httplib::Request &request) {
	if (request.get_header_value_count("Authorization") != 1) {
		return std::nullopt;
	}
	const std::string authorization =
		request.get_header_value("Authorization");
	constexpr char scheme[] = "bearer ";
	if (authorization.size() <= sizeof(scheme) - 1 ||
		!std::equal(std::begin(scheme), std::end(scheme) - 1,
					authorization.begin(),
					[](char expected, char actual) {
						return expected ==
							   static_cast<char>(std::tolower(
								   static_cast<unsigned char>(actual)));
					})) {
		return std::nullopt;
	}
	const std::string token = authorization.substr(sizeof(scheme) - 1);
	if (token.find_first_of(" \t\r\n") != std::string::npos ||
		token.size() > 256) {
		return std::nullopt;
	}
	return token;
}

httplib::Server::HandlerResponse authorizeApiRequest(
	Auth::AuthProvider &auth, const httplib::Request &request,
	httplib::Response &response) {
	if (!(request.method == "GET" && request.path == "/status/health")) {
		const std::string supportedVersion = std::to_string(SCHEMA_VERSION);
		response.set_header(SCHEMA_VERSION_HEADER, supportedVersion);
		if (request.get_header_value(SCHEMA_VERSION_HEADER) !=
			supportedVersion) {
			reject(response, 400, "unsupported_schema_version",
				   "Missing or unsupported API schema version");
			return httplib::Server::HandlerResponse::Handled;
		}
	}

	if (isPublicRoute(request)) {
		return httplib::Server::HandlerResponse::Unhandled;
	}

	const auto token = bearerToken(request);
	if (!token) {
		response.set_header("WWW-Authenticate", "Bearer");
		reject(response, 401, "authentication_required",
			   "A valid Bearer session is required");
		Logger::API::log("request_rejected code=authentication_required",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	std::optional<Auth::Identity> identity;
	try {
		identity = auth.authenticateSession(*token);
	} catch (const std::exception &) {
		reject(response, 500, "authentication_unavailable",
			   "Authentication service is unavailable");
		Logger::API::log("operation_failed operation=authenticate_session "
						 "error_code=authentication_storage_error",
						 Logger::Level::ERROR);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (!identity) {
		response.set_header("WWW-Authenticate", "Bearer");
		reject(response, 401, "invalid_session",
			   "A valid Bearer session is required");
		Logger::API::log("request_rejected code=invalid_session",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	if (requiresFirewallOperator(request) &&
		identity->role == Auth::Role::Viewer) {
		reject(response, 403, "insufficient_role",
			   "Operator or administrator role is required");
		Logger::API::log("request_rejected code=insufficient_role",
						 Logger::Level::WARNING);
		return httplib::Server::HandlerResponse::Handled;
	}

	return httplib::Server::HandlerResponse::Unhandled;
}

} // namespace HttpApi
