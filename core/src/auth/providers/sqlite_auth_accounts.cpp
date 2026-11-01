// SQLite auth provider account lifecycle: bootstrap, management, and setup
// tokens.

#include "sqlite_auth_provider_impl.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace Auth {
namespace {
using Auth::Detail::hashPassword;
using Auth::Detail::hashSessionToken;
using Auth::Detail::makeUuid;
using Auth::Detail::normalizeUsername;
using Auth::Detail::validatePassword;
using Auth::Detail::verifyPassword;
using AuthStorage::Statement;
using AuthStorage::Transaction;
using SqliteProviderDetail::INVALID_USERNAME_MESSAGE;
using SqliteProviderDetail::roleValue;
using SqliteProviderDetail::unixTimeNow;
} // namespace

Identity SqliteAuthProvider::bootstrapAdministrator(std::string_view username,
													std::string_view password) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	const std::string			normalized = normalizeUsername(username);
	if (normalized.empty()) {
		throw std::runtime_error(INVALID_USERNAME_MESSAGE);
	}
	try {
		validatePassword(password, impl_->passwordPolicy);
	} catch (const std::runtime_error &error) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									error.what());
	}
	const std::string passwordHash =
		hashPassword(password, impl_->argon2idParameters);
	const std::string userId = makeUuid();
	const auto		  now	 = std::chrono::duration_cast<std::chrono::seconds>(
						   std::chrono::system_clock::now().time_since_epoch())
						 .count();

	Transaction transaction(impl_->database);
	{
		Statement activeAdmin(
			impl_->database,
			"SELECT 1 FROM users WHERE role = 2 AND enabled = 1 LIMIT 1");
		const int result = sqlite3_step(activeAdmin.get());
		if (result == SQLITE_ROW) {
			throw std::runtime_error("An active administrator already exists");
		}
		if (result != SQLITE_DONE) {
			throw std::runtime_error(
				std::string("Unable to inspect administrator accounts: ") +
				sqlite3_errmsg(impl_->database));
		}
	}
	Statement insert(
		impl_->database,
		"INSERT INTO users "
		"(id, username, normalized_username, role, password_hash, enabled, "
		"created_at, updated_at) VALUES (?1, ?2, ?2, 2, ?3, 1, ?4, ?4)");
	insert.bindText(1, userId);
	insert.bindText(2, normalized);
	insert.bindText(3, passwordHash);
	insert.bindInteger(4, now);
	insert.execute();
	transaction.commit();
	return Identity{userId, normalized, Role::Administrator};
}

std::vector<Account> SqliteAuthProvider::listAccounts() {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	Statement					query(impl_->database,
									  "SELECT id, username, role, enabled, setup_pending FROM "
														"users ORDER BY normalized_username");
	std::vector<Account>		accounts;
	for (;;) {
		const int result = sqlite3_step(query.get());
		if (result == SQLITE_DONE) {
			return accounts;
		}
		if (result != SQLITE_ROW) {
			throw std::runtime_error(
				std::string("Unable to list local accounts: ") +
				sqlite3_errmsg(impl_->database));
		}
		accounts.push_back(impl_->accountFrom(query.get()));
	}
}

AccountSetup SqliteAuthProvider::createAccount(std::string_view username,
											   Role				role) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	const std::string			normalized = normalizeUsername(username);
	if (normalized.empty()) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									INVALID_USERNAME_MESSAGE);
	}
	const int		   storedRole = roleValue(role);
	const std::string  userId	  = makeUuid();
	const std::string  token	  = Auth::Detail::createSessionToken();
	const std::string  tokenHash  = hashSessionToken(token);
	const std::int64_t now		  = unixTimeNow();
	Transaction		   transaction(impl_->database);
	{
		Statement existing(
			impl_->database,
			"SELECT 1 FROM users WHERE normalized_username = ?1 LIMIT 1");
		existing.bindText(1, normalized);
		const int result = sqlite3_step(existing.get());
		if (result == SQLITE_ROW) {
			throw AccountOperationError(AccountOperationError::Code::Conflict,
										"Username is already in use");
		}
		if (result != SQLITE_DONE) {
			throw std::runtime_error(
				std::string("Unable to check account username: ") +
				sqlite3_errmsg(impl_->database));
		}
	}
	Statement insert(
		impl_->database,
		"INSERT INTO users "
		"(id, username, normalized_username, role, password_hash, enabled, "
		"created_at, updated_at, setup_pending) "
		"VALUES (?1, ?2, ?2, ?3, '', 0, ?4, ?4, 1)");
	insert.bindText(1, userId);
	insert.bindText(2, normalized);
	insert.bindInteger(3, storedRole);
	insert.bindInteger(4, now);
	insert.execute();
	Statement setup(impl_->database, "INSERT INTO account_setup_tokens "
									 "(token_hash, user_id, created_at, "
									 "expires_at) VALUES (?1, ?2, ?3, ?4)");
	setup.bindText(1, tokenHash);
	setup.bindText(2, userId);
	setup.bindInteger(3, now);
	setup.bindInteger(
		4, now + AppConfigLimits::ACCOUNT_SETUP_TOKEN_LIFETIME_SECONDS);
	setup.execute();
	transaction.commit();
	return {
		Account{Identity{userId, normalized, role}, false, true},
		  token
	   };
}

Account SqliteAuthProvider::updateAccount(std::string_view	   id,
										  const AccountUpdate &update) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	if (id.empty() || id.size() > AppConfigLimits::MAX_ACCOUNT_ID_LENGTH ||
		(!update.username && !update.role)) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									"Account update is invalid");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	Transaction					transaction(impl_->database);
	Statement					current(
		  impl_->database,
		  "SELECT id, username, role, enabled, setup_pending FROM users "
						  "WHERE id = ?1");
	current.bindText(1, id);
	const int currentResult = sqlite3_step(current.get());
	if (currentResult == SQLITE_DONE) {
		throw AccountOperationError(AccountOperationError::Code::NotFound,
									"Account was not found");
	}
	if (currentResult != SQLITE_ROW) {
		throw std::runtime_error(std::string("Unable to query account: ") +
								 sqlite3_errmsg(impl_->database));
	}
	const Account	  existing = impl_->accountFrom(current.get());
	const std::string username = update.username
									 ? normalizeUsername(*update.username)
									 : existing.identity.username;
	if (username.empty()) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									INVALID_USERNAME_MESSAGE);
	}
	const Role role		  = update.role.value_or(existing.identity.role);
	const int  storedRole = roleValue(role);
	if (username != existing.identity.username) {
		Statement duplicate(
			impl_->database,
			"SELECT 1 FROM users WHERE normalized_username = ?1 AND id != ?2 "
			"LIMIT 1");
		duplicate.bindText(1, username);
		duplicate.bindText(2, id);
		const int result = sqlite3_step(duplicate.get());
		if (result == SQLITE_ROW) {
			throw AccountOperationError(AccountOperationError::Code::Conflict,
										"Username is already in use");
		}
		if (result != SQLITE_DONE) {
			throw std::runtime_error(
				std::string("Unable to check account username: ") +
				sqlite3_errmsg(impl_->database));
		}
	}
	if (existing.enabled && existing.identity.role == Role::Administrator &&
		role != Role::Administrator) {
		Statement otherAdmin(
			impl_->database,
			"SELECT COUNT(*) FROM users WHERE role = 2 AND enabled = 1 "
			"AND id != ?1");
		otherAdmin.bindText(1, id);
		if (sqlite3_step(otherAdmin.get()) != SQLITE_ROW) {
			throw std::runtime_error(
				"Unable to verify active administrator accounts");
		}
		if (sqlite3_column_int64(otherAdmin.get(), 0) == 0) {
			throw AccountOperationError(
				AccountOperationError::Code::LastAdministrator,
				"The last active administrator cannot be demoted");
		}
	}
	Statement change(
		impl_->database,
		"UPDATE users SET username = ?1, normalized_username = ?1, role = ?2, "
		"updated_at = ?3 WHERE id = ?4");
	change.bindText(1, username);
	change.bindInteger(2, storedRole);
	change.bindInteger(3, unixTimeNow());
	change.bindText(4, id);
	change.execute();
	Statement revoke(impl_->database,
					 "DELETE FROM api_sessions WHERE user_id = ?1");
	revoke.bindText(1, id);
	revoke.execute();
	transaction.commit();
	return Account{
		Identity{existing.identity.id, username, role},
		existing.enabled,
		existing.setup_pending
	  };
}

void SqliteAuthProvider::disableAccount(std::string_view id) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	if (id.empty() || id.size() > AppConfigLimits::MAX_ACCOUNT_ID_LENGTH) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									"Account ID is invalid");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	Transaction					transaction(impl_->database);
	Statement					current(impl_->database,
										"SELECT role, enabled FROM users WHERE id = ?1");
	current.bindText(1, id);
	const int currentResult = sqlite3_step(current.get());
	if (currentResult == SQLITE_DONE) {
		throw AccountOperationError(AccountOperationError::Code::NotFound,
									"Account was not found");
	}
	if (currentResult != SQLITE_ROW) {
		throw std::runtime_error(std::string("Unable to query account: ") +
								 sqlite3_errmsg(impl_->database));
	}
	if (sqlite3_column_int(current.get(), 0) == 2 &&
		sqlite3_column_int(current.get(), 1) != 0) {
		Statement otherAdmin(
			impl_->database,
			"SELECT COUNT(*) FROM users WHERE role = 2 AND enabled = 1 "
			"AND id != ?1");
		otherAdmin.bindText(1, id);
		if (sqlite3_step(otherAdmin.get()) != SQLITE_ROW) {
			throw std::runtime_error(
				"Unable to verify active administrator accounts");
		}
		if (sqlite3_column_int64(otherAdmin.get(), 0) == 0) {
			throw AccountOperationError(
				AccountOperationError::Code::LastAdministrator,
				"The last active administrator cannot be disabled");
		}
	}
	Statement disable(
		impl_->database,
		"UPDATE users SET enabled = 0, setup_pending = 0, updated_at = ?1 "
		"WHERE id = ?2");
	disable.bindInteger(1, unixTimeNow());
	disable.bindText(2, id);
	disable.execute();
	Statement sessions(impl_->database,
					   "DELETE FROM api_sessions WHERE user_id = ?1");
	sessions.bindText(1, id);
	sessions.execute();
	Statement tokens(impl_->database,
					 "DELETE FROM account_setup_tokens WHERE user_id = ?1");
	tokens.bindText(1, id);
	tokens.execute();
	transaction.commit();
}

AccountSetup SqliteAuthProvider::issueAccountSetupToken(std::string_view id) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	if (id.empty() || id.size() > AppConfigLimits::MAX_ACCOUNT_ID_LENGTH) {
		throw AccountOperationError(AccountOperationError::Code::Invalid,
									"Account ID is invalid");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	Transaction					transaction(impl_->database);
	Statement					current(
		  impl_->database,
		  "SELECT id, username, role, enabled, setup_pending FROM users "
						  "WHERE id = ?1");
	current.bindText(1, id);
	const int currentResult = sqlite3_step(current.get());
	if (currentResult == SQLITE_DONE) {
		throw AccountOperationError(AccountOperationError::Code::NotFound,
									"Account was not found");
	}
	if (currentResult != SQLITE_ROW) {
		throw std::runtime_error(std::string("Unable to query account: ") +
								 sqlite3_errmsg(impl_->database));
	}
	const Account account = impl_->accountFrom(current.get());
	if (!account.enabled && !account.setup_pending) {
		throw AccountOperationError(
			AccountOperationError::Code::Invalid,
			"Disabled accounts cannot receive setup tokens");
	}
	const std::string  token	 = Auth::Detail::createSessionToken();
	const std::string  tokenHash = hashSessionToken(token);
	const std::int64_t now		 = unixTimeNow();
	Statement		   revokeTokens(
		 impl_->database, "DELETE FROM account_setup_tokens WHERE user_id = ?1");
	revokeTokens.bindText(1, id);
	revokeTokens.execute();
	Statement insert(impl_->database, "INSERT INTO account_setup_tokens "
									  "(token_hash, user_id, created_at, "
									  "expires_at) VALUES (?1, ?2, ?3, ?4)");
	insert.bindText(1, tokenHash);
	insert.bindText(2, id);
	insert.bindInteger(3, now);
	insert.bindInteger(
		4, now + AppConfigLimits::ACCOUNT_SETUP_TOKEN_LIFETIME_SECONDS);
	insert.execute();
	Statement revokeSessions(impl_->database,
							 "DELETE FROM api_sessions WHERE user_id = ?1");
	revokeSessions.bindText(1, id);
	revokeSessions.execute();
	transaction.commit();
	return {account, token};
}

Identity SqliteAuthProvider::completeAccountSetup(std::string_view token,
												  std::string_view password) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	if (token.size() != AppConfigLimits::TOKEN_HEX_LENGTH ||
		!std::all_of(token.begin(), token.end(), [](unsigned char character) {
			return std::isxdigit(character) != 0;
		})) {
		throw AccountOperationError(AccountOperationError::Code::InvalidToken,
									"Setup token is invalid or expired");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	Transaction					transaction(impl_->database);
	const std::string			tokenHash = hashSessionToken(token);
	const std::int64_t			now		  = unixTimeNow();
	Statement					query(
		  impl_->database,
		  "SELECT users.id, users.username, users.role, users.enabled, "
						  "users.setup_pending, account_setup_tokens.expires_at "
						  "FROM account_setup_tokens JOIN users ON users.id = "
						  "account_setup_tokens.user_id WHERE "
						  "account_setup_tokens.token_hash = ?1");
	query.bindText(1, tokenHash);
	const int queryResult = sqlite3_step(query.get());
	if (queryResult == SQLITE_DONE) {
		throw AccountOperationError(AccountOperationError::Code::InvalidToken,
									"Setup token is invalid or expired");
	}
	if (queryResult != SQLITE_ROW) {
		throw std::runtime_error(
			std::string("Unable to validate setup token: ") +
			sqlite3_errmsg(impl_->database));
	}
	const Account account = impl_->accountFrom(query.get());
	const auto	  expiry  = sqlite3_column_int64(query.get(), 5);
	if ((!account.enabled && !account.setup_pending) || expiry <= now) {
		Statement remove(
			impl_->database,
			"DELETE FROM account_setup_tokens WHERE token_hash = ?1");
		remove.bindText(1, tokenHash);
		remove.execute();
		transaction.commit();
		throw AccountOperationError(AccountOperationError::Code::InvalidToken,
									"Setup token is invalid or expired");
	}
	validatePassword(password, impl_->passwordPolicy);
	const std::string passwordHash =
		hashPassword(password, impl_->argon2idParameters);
	Statement update(
		impl_->database,
		"UPDATE users SET password_hash = ?1, enabled = 1, setup_pending = 0, "
		"updated_at = ?2 WHERE id = ?3");
	update.bindText(1, passwordHash);
	update.bindInteger(2, now);
	update.bindText(3, account.identity.id);
	update.execute();
	Statement removeTokens(
		impl_->database, "DELETE FROM account_setup_tokens WHERE user_id = ?1");
	removeTokens.bindText(1, account.identity.id);
	removeTokens.execute();
	Statement removeSessions(impl_->database,
							 "DELETE FROM api_sessions WHERE user_id = ?1");
	removeSessions.bindText(1, account.identity.id);
	removeSessions.execute();
	transaction.commit();
	return account.identity;
}

} // namespace Auth
