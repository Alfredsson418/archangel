#pragma once

// Shared fixtures for the HTTP authentication, login, and account API tests.

#include "auth/auth_provider.hpp"
#include "cpp-httplib/cpp-httplib.hpp"
#include "http/api/schema.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace TestSupport {
// In-memory AuthProvider with fixed viewer, operator, and admin tokens.
class MockAuthProvider final : public Auth::AuthProvider {
  public:
	std::optional<Auth::Session> login(std::string_view username,
									   std::string_view password) override {
		if (username != "admin" || password != "correct test password") {
			return std::nullopt;
		}
		return Auth::Session{
			"admin-token", {"user-id", "admin", Auth::Role::Administrator}
		  };
	}

	std::optional<Auth::Identity>
	authenticateSession(std::string_view token) override {
		if (storage_failure) {
			throw std::runtime_error("private storage detail");
		}
		if (token == "viewer-token") {
			return Auth::Identity{"viewer-id", "viewer", Auth::Role::Viewer};
		}
		if (token == "operator-token" && second_operator) {
			return Auth::Identity{"operator-two-id", "operator-two",
								  Auth::Role::Operator};
		}
		if (token == "operator-token") {
			return Auth::Identity{"operator-id", "operator",
								  Auth::Role::Operator};
		}
		if (token == "admin-token") {
			return Auth::Identity{"user-id", "admin",
								  Auth::Role::Administrator};
		}
		return std::nullopt;
	}

	void revokeSession(std::string_view token) override {
		revoked_token = token;
	}

	Auth::Identity bootstrapAdministrator(std::string_view,
										  std::string_view) override {
		throw std::runtime_error("not used");
	}

	Auth::Identity recoverAdministrator(std::string_view,
										std::string_view) override {
		throw std::runtime_error("not used");
	}

	std::vector<Auth::Account> listAccounts() override {
		return {
			Auth::Account{
						  Auth::Identity{"account-id", "operator", Auth::Role::Operator},
						  true, false}
		};
	}

	Auth::AccountSetup createAccount(std::string_view username,
									 Auth::Role		  role) override {
		return {
			Auth::Account{
						  Auth::Identity{"new-account-id", std::string(username), role},
						  false, true},
			"setup-token"
		 };
	}

	Auth::Account updateAccount(std::string_view		   id,
								const Auth::AccountUpdate &update) override {
		return {
			Auth::Identity{std::string(id),
						   update.username.value_or("operator"),
						   update.role.value_or(Auth::Role::Operator)},
			true, false
		   };
	}

	void disableAccount(std::string_view id) override {
		disabled_account_id = id;
	}

	Auth::AccountSetup issueAccountSetupToken(std::string_view id) override {
		return {
			Auth::Account{Auth::Identity{std::string(id), "operator",
										 Auth::Role::Operator},
						  true, false},
			"replacement-token"
		   };
	}

	Auth::Identity completeAccountSetup(std::string_view,
										std::string_view) override {
		return {"new-account-id", "operator", Auth::Role::Operator};
	}

	bool		storage_failure = false;
	bool		second_operator = false;
	std::string disabled_account_id;
	std::string revoked_token;
};

// Builds a request carrying the supported API schema-version header.
inline httplib::Request requestWithSchema(const std::string &method,
										  const std::string &path) {
	httplib::Request request;
	request.method = method;
	request.path   = path;
	request.set_header(HttpApi::SCHEMA_VERSION_HEADER,
					   std::to_string(HttpApi::SCHEMA_VERSION));
	return request;
}
} // namespace TestSupport
