#include "../../../include/http/api/accounts.hpp"
#include "api_common.hpp"

#include <string>
#include <string_view>

namespace HttpApi {
namespace {
constexpr std::size_t MAX_ACCOUNT_BODY_BYTES = 16 * 1024;
constexpr std::size_t MAX_ACCOUNT_ID_BYTES = 64;

const char *roleName(Auth::Role role) {
	switch (role) {
	case Auth::Role::Viewer:
		return "viewer";
	case Auth::Role::Operator:
		return "operator";
	case Auth::Role::Administrator:
		return "administrator";
	}
	return "unknown";
}

bool parseRole(const Detail::Json &value, Auth::Role &role) {
	if (!value.is_string()) {
		return false;
	}
	const std::string name = value.get<std::string>();
	if (name == "viewer") {
		role = Auth::Role::Viewer;
	} else if (name == "operator") {
		role = Auth::Role::Operator;
	} else if (name == "administrator") {
		role = Auth::Role::Administrator;
	} else {
		return false;
	}
	return true;
}

Detail::Json accountJson(const Auth::Account &account) {
	return {
		{"id", account.identity.id},
		{"username", account.identity.username},
		{"role", roleName(account.identity.role)},
		{"enabled", account.enabled},
		{"setup_pending", account.setup_pending},
	};
}

bool parseBody(const httplib::Request &request, Detail::Json &document,
			   httplib::Response &response) {
	if (request.body.size() > MAX_ACCOUNT_BODY_BYTES) {
		Detail::sendError(response,
						  ApiError(413, "request_too_large",
								   "Account request is too large"));
		return false;
	}
	try {
		document = Detail::Json::parse(request.body);
	} catch (const Detail::Json::exception &) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account request is invalid"));
		return false;
	}
	if (!document.is_object()) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account request is invalid"));
		return false;
	}
	return true;
}

bool hasOnly(const Detail::Json &document,
			 std::initializer_list<const char *> keys) {
	for (auto field = document.begin(); field != document.end(); ++field) {
		bool known = false;
		for (const char *key : keys) {
			known = known || field.key() == key;
		}
		if (!known) {
			return false;
		}
	}
	return true;
}

void sendAccountError(httplib::Response &response,
					  const Auth::AccountOperationError &error) {
	int status = 400;
	const char *code = "invalid_request";
	switch (error.code) {
	case Auth::AccountOperationError::Code::Invalid:
		break;
	case Auth::AccountOperationError::Code::NotFound:
		status = 404;
		code = "account_not_found";
		break;
	case Auth::AccountOperationError::Code::Conflict:
		status = 409;
		code = "account_conflict";
		break;
	case Auth::AccountOperationError::Code::LastAdministrator:
		status = 409;
		code = "last_administrator";
		break;
	case Auth::AccountOperationError::Code::InvalidToken:
		status = 400;
		code = "invalid_setup_token";
		break;
	}
	response.status = status;
	response.set_content(
		Detail::Json{{"error", error.what()}, {"code", code}}.dump(),
		"application/json");
}

template <typename Operation>
void handleAccountOperation(httplib::Response &response,
							const char *operation, Operation &&run) {
	try {
		run();
	} catch (const Auth::AccountOperationError &error) {
		sendAccountError(response, error);
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, operation, error,
								   "account_storage_error",
								   "Account operation failed");
	}
}

} // namespace

void getAccounts(Auth::AuthProvider &auth, const httplib::Request &,
				 httplib::Response &response) {
	handleAccountOperation(response, "GET /api/v1/accounts", [&] {
		Detail::Json accounts = Detail::Json::array();
		for (const Auth::Account &account : auth.listAccounts()) {
			accounts.push_back(accountJson(account));
		}
		response.status = 200;
		response.set_content(Detail::Json{{"accounts", std::move(accounts)}}.dump(),
							 "application/json");
	});
}

void createAccount(Auth::AuthProvider &auth, const httplib::Request &request,
				   httplib::Response &response) {
	Detail::Json document;
	if (!parseBody(request, document, response)) {
		return;
	}
	if (!hasOnly(document, {"username", "role"}) ||
		document.size() != 2 || !document["username"].is_string()) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account request is invalid"));
		return;
	}
	Auth::Role role;
	if (!parseRole(document["role"], role)) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account role is invalid"));
		return;
	}
	const std::string username = document["username"].get<std::string>();
	handleAccountOperation(response, "POST /api/v1/accounts", [&] {
		const Auth::AccountSetup created = auth.createAccount(username, role);
		response.status = 201;
		response.set_content(
			Detail::Json{{"account", accountJson(created.account)},
						 {"setup_token", created.setup_token}}
				.dump(),
			"application/json");
	});
}

void updateAccount(Auth::AuthProvider &auth, const httplib::Request &request,
				   httplib::Response &response) {
	Detail::Json document;
	if (!parseBody(request, document, response)) {
		return;
	}
	if (!hasOnly(document, {"id", "username", "role"}) ||
		!document.contains("id") || !document["id"].is_string() ||
		document["id"].get<std::string>().empty() ||
		document["id"].get<std::string>().size() > MAX_ACCOUNT_ID_BYTES) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account update is invalid"));
		return;
	}
	Auth::AccountUpdate update;
	if (document.contains("username")) {
		if (!document["username"].is_string()) {
			Detail::sendError(response,
							  ApiError(400, "invalid_request",
									   "Account username is invalid"));
			return;
		}
		update.username = document["username"].get<std::string>();
	}
	if (document.contains("role")) {
		Auth::Role role;
		if (!parseRole(document["role"], role)) {
			Detail::sendError(response,
							  ApiError(400, "invalid_request",
									   "Account role is invalid"));
			return;
		}
		update.role = role;
	}
	const std::string id = document["id"].get<std::string>();
	handleAccountOperation(response, "PATCH /api/v1/accounts", [&] {
		response.status = 200;
		response.set_content(
			Detail::Json{{"account", accountJson(auth.updateAccount(id, update))}}
				.dump(),
			"application/json");
	});
}

void disableAccount(Auth::AuthProvider &auth, const httplib::Request &request,
					httplib::Response &response) {
	Detail::Json document;
	if (!parseBody(request, document, response)) {
		return;
	}
	if (!hasOnly(document, {"id"}) || document.size() != 1 ||
		!document["id"].is_string() ||
		document["id"].get<std::string>().empty() ||
		document["id"].get<std::string>().size() > MAX_ACCOUNT_ID_BYTES) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account request is invalid"));
		return;
	}
	const std::string id = document["id"].get<std::string>();
	handleAccountOperation(response, "POST /api/v1/accounts/disable", [&] {
		auth.disableAccount(id);
		response.status = 204;
	});
}

void issueAccountSetupToken(Auth::AuthProvider &auth,
							const httplib::Request &request,
							httplib::Response &response) {
	Detail::Json document;
	if (!parseBody(request, document, response)) {
		return;
	}
	if (!hasOnly(document, {"id"}) || document.size() != 1 ||
		!document["id"].is_string() ||
		document["id"].get<std::string>().empty() ||
		document["id"].get<std::string>().size() > MAX_ACCOUNT_ID_BYTES) {
		Detail::sendError(response,
						  ApiError(400, "invalid_request",
								   "Account request is invalid"));
		return;
	}
	const std::string id = document["id"].get<std::string>();
	handleAccountOperation(response, "POST /api/v1/accounts/setup-token", [&] {
		const Auth::AccountSetup setup = auth.issueAccountSetupToken(id);
		response.status = 200;
		response.set_content(
			Detail::Json{{"account", accountJson(setup.account)},
						 {"setup_token", setup.setup_token}}
				.dump(),
			"application/json");
	});
}

} // namespace HttpApi
