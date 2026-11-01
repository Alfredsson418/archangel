#pragma once

// Private to the SQLite auth provider: state and helpers shared by its
// session (sqlite_auth_provider.cpp) and account-lifecycle
// (sqlite_auth_accounts.cpp) translation units.

#include "../auth_crypto.hpp"
#include "auth/providers/sqlite_auth_provider.hpp"
#include "sqlite_auth_storage.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace Auth {
namespace SqliteProviderDetail {
inline const std::string INVALID_USERNAME_MESSAGE =
	"Username must be " + std::to_string(AppConfigLimits::MIN_USERNAME_LENGTH) +
	"-" + std::to_string(AppConfigLimits::MAX_USERNAME_LENGTH) +
	" ASCII letters, digits, dots, underscores, or hyphens";

inline Auth::Role parseRole(int role) {
	switch (role) {
	case 0:
		return Auth::Role::Viewer;
	case 1:
		return Auth::Role::Operator;
	case 2:
		return Auth::Role::Administrator;
	default:
		throw std::runtime_error(
			"Authentication database contains invalid role");
	}
}

inline int roleValue(Auth::Role role) {
	switch (role) {
	case Auth::Role::Viewer:
		return 0;
	case Auth::Role::Operator:
		return 1;
	case Auth::Role::Administrator:
		return 2;
	}
	throw Auth::AccountOperationError(
		Auth::AccountOperationError::Code::Invalid, "Account role is invalid");
}

inline std::int64_t unixTimeNow() {
	return std::chrono::duration_cast<std::chrono::seconds>(
			   std::chrono::system_clock::now().time_since_epoch())
		.count();
}
} // namespace SqliteProviderDetail

struct SqliteAuthProvider::Impl {
	explicit Impl(const std::string &path, std::chrono::seconds idle,
				  std::chrono::seconds absolute, PasswordPolicy policy,
				  Argon2idParameters argonParameters)
		: idleTimeout(idle), absoluteTimeout(absolute), passwordPolicy(policy),
		  argon2idParameters(argonParameters) {
		if (idleTimeout <= std::chrono::seconds::zero() ||
			absoluteTimeout <= idleTimeout) {
			throw std::runtime_error("Invalid API session lifetime settings");
		}
		if (passwordPolicy.minimumCharacters <
				AppConfigLimits::MIN_PASSWORD_LENGTH ||
			passwordPolicy.maximumCharacters >
				AppConfigLimits::MAX_PASSWORD_LENGTH ||
			passwordPolicy.minimumCharacters >
				passwordPolicy.maximumCharacters) {
			throw std::runtime_error(
				"Invalid local-account password policy settings");
		}
		if (argon2idParameters.memoryKiB <
				AppConfigLimits::MIN_ARGON2ID_MEMORY_KIB ||
			argon2idParameters.memoryKiB >
				AppConfigLimits::MAX_ARGON2ID_MEMORY_KIB ||
			argon2idParameters.iterations <
				AppConfigLimits::MIN_ARGON2ID_ITERATIONS ||
			argon2idParameters.iterations >
				AppConfigLimits::MAX_ARGON2ID_ITERATIONS ||
			argon2idParameters.parallelism <
				AppConfigLimits::MIN_ARGON2ID_PARALLELISM ||
			argon2idParameters.parallelism >
				AppConfigLimits::MAX_ARGON2ID_PARALLELISM ||
			argon2idParameters.memoryKiB < argon2idParameters.parallelism * 8) {
			throw std::runtime_error(
				"Invalid Argon2id password hashing settings");
		}
		storage			  = std::make_unique<AuthStorage::Database>(path);
		database		  = storage->get();
		dummyPasswordHash = Detail::hashPassword(
			"archangel-dummy-password-value", argon2idParameters);
	}

	Identity identityFrom(sqlite3_stmt *statement) const {
		const auto *id =
			reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
		const auto *username =
			reinterpret_cast<const char *>(sqlite3_column_text(statement, 1));
		if (id == nullptr || username == nullptr) {
			throw std::runtime_error(
				"Authentication database contains an invalid user");
		}
		return Identity{
			id, username,
			SqliteProviderDetail::parseRole(sqlite3_column_int(statement, 2))};
	}

	Account accountFrom(sqlite3_stmt *statement) const {
		return Account{identityFrom(statement),
					   sqlite3_column_int(statement, 3) != 0,
					   sqlite3_column_int(statement, 4) != 0};
	}

	std::unique_ptr<AuthStorage::Database> storage;
	sqlite3								  *database = nullptr;
	std::string							   dummyPasswordHash;
	std::chrono::seconds				   idleTimeout;
	std::chrono::seconds				   absoluteTimeout;
	PasswordPolicy						   passwordPolicy;
	Argon2idParameters					   argon2idParameters;
	std::mutex							   databaseMutex;
};

} // namespace Auth
