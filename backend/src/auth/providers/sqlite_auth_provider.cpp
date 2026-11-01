// SQLite auth provider construction, login, and session handling.

#include "sqlite_auth_provider_impl.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

namespace Auth {

namespace {
using Detail::hashPassword;
using Detail::hashSessionToken;
using Detail::INVALID_USERNAME_MESSAGE;
using Detail::makeUuid;
using Detail::normalizeUsername;
using Detail::roleValue;
using Detail::Statement;
using Detail::Transaction;
using Detail::unixTimeNow;
using Detail::validatePassword;
using Detail::verifyPassword;
} // namespace

SqliteAuthProvider::SqliteAuthProvider(std::string			databasePath,
									   std::chrono::seconds idleTimeout,
									   std::chrono::seconds absoluteTimeout,
									   PasswordPolicy		passwordPolicy,
									   Argon2idParameters	argon2idParameters)
	: impl_(std::make_unique<Impl>(databasePath, idleTimeout, absoluteTimeout,
								   passwordPolicy, argon2idParameters)) {}

SqliteAuthProvider::~SqliteAuthProvider() = default;
SqliteAuthProvider::SqliteAuthProvider(SqliteAuthProvider &&) noexcept =
	default;
SqliteAuthProvider &
SqliteAuthProvider::operator=(SqliteAuthProvider &&) noexcept = default;

std::optional<Session> SqliteAuthProvider::login(std::string_view username,
												 std::string_view password) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	const bool					passwordTooLong =
		password.size() > Config::Limits::MAX_PASSWORD_BYTES;
	const std::string_view boundedPassword =
		passwordTooLong ? password.substr(0, Config::Limits::MAX_PASSWORD_BYTES)
						: password;
	const std::string normalized = normalizeUsername(username);
	if (normalized.empty()) {
		verifyPassword(impl_->dummyPasswordHash, boundedPassword);
		return std::nullopt;
	}
	Statement userQuery(
		impl_->database,
		"SELECT id, username, role, password_hash, enabled FROM users "
		"WHERE normalized_username = ?1");
	userQuery.bindText(1, normalized);
	const int queryResult = sqlite3_step(userQuery.get());
	if (queryResult != SQLITE_ROW) {
		if (queryResult != SQLITE_DONE) {
			throw std::runtime_error(
				std::string("Unable to query local account: ") +
				sqlite3_errmsg(impl_->database));
		}
		verifyPassword(impl_->dummyPasswordHash, boundedPassword);
		return std::nullopt;
	}
	const auto *hash =
		reinterpret_cast<const char *>(sqlite3_column_text(userQuery.get(), 3));
	const bool enabled = sqlite3_column_int(userQuery.get(), 4) != 0;
	if (!enabled) {
		verifyPassword(impl_->dummyPasswordHash, boundedPassword);
		return std::nullopt;
	}
	if (hash == nullptr) {
		throw std::runtime_error(
			"Authentication database contains an invalid password hash");
	}
	const std::string passwordHash(hash);
	const bool passwordValid = verifyPassword(passwordHash, boundedPassword);
	if (passwordTooLong || !passwordValid) {
		return std::nullopt;
	}
	const Identity identity = impl_->identityFrom(userQuery.get());
	// Upgrade hashes made before the configured Argon2id cost was raised.
	const std::optional<std::string> upgradedHash =
		Detail::needsRehash(passwordHash, impl_->argon2idParameters)
			? std::optional<std::string>(
				  hashPassword(boundedPassword, impl_->argon2idParameters))
			: std::nullopt;

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count();
	const auto		  expiry	= now + impl_->absoluteTimeout.count();
	const std::string token		= Detail::createSessionToken();
	const std::string tokenHash = Detail::hashSessionToken(token);
	Transaction		  transaction(impl_->database);
	{
		Statement removeExpired(
			impl_->database,
			"DELETE FROM api_sessions WHERE expires_at <= ?1 OR "
			"last_used_at <= ?2");
		removeExpired.bindInteger(1, now);
		removeExpired.bindInteger(2, now - impl_->idleTimeout.count());
		removeExpired.execute();
	}
	if (upgradedHash) {
		Statement rehash(impl_->database,
						 "UPDATE users SET password_hash = ?1 WHERE id = ?2");
		rehash.bindText(1, *upgradedHash);
		rehash.bindText(2, identity.id);
		rehash.execute();
	}
	{
		Statement insert(
			impl_->database,
			"INSERT INTO api_sessions "
			"(token_hash, user_id, created_at, last_used_at, expires_at) "
			"VALUES (?1, ?2, ?3, ?3, ?4)");
		insert.bindText(1, tokenHash);
		insert.bindText(2, identity.id);
		insert.bindInteger(3, now);
		insert.bindInteger(4, expiry);
		insert.execute();
	}
	transaction.commit();
	return Session{token, identity};
}

std::optional<Identity>
SqliteAuthProvider::authenticateSession(std::string_view token) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	if (token.size() != Config::Limits::TOKEN_HEX_LENGTH ||
		!std::all_of(token.begin(), token.end(), [](unsigned char character) {
			return std::isxdigit(character) != 0;
		})) {
		return std::nullopt;
	}
	const std::string tokenHash = Detail::hashSessionToken(token);
	const auto		  now = std::chrono::duration_cast<std::chrono::seconds>(
							std::chrono::system_clock::now().time_since_epoch())
						 .count();
	Transaction transaction(impl_->database);
	Statement	query(
		  impl_->database,
		  "SELECT users.id, users.username, users.role, api_sessions.expires_at, "
		  "api_sessions.last_used_at FROM api_sessions "
		  "JOIN users ON users.id = api_sessions.user_id "
		  "WHERE api_sessions.token_hash = ?1 AND users.enabled = 1");
	query.bindText(1, tokenHash);
	const int queryResult = sqlite3_step(query.get());
	if (queryResult == SQLITE_DONE) {
		transaction.commit();
		return std::nullopt;
	}
	if (queryResult != SQLITE_ROW) {
		throw std::runtime_error(std::string("Unable to query API session: ") +
								 sqlite3_errmsg(impl_->database));
	}
	const auto expiry	= sqlite3_column_int64(query.get(), 3);
	const auto lastUsed = sqlite3_column_int64(query.get(), 4);
	if (expiry <= now || lastUsed <= now - impl_->idleTimeout.count()) {
		Statement remove(impl_->database,
						 "DELETE FROM api_sessions WHERE token_hash = ?1");
		remove.bindText(1, tokenHash);
		remove.execute();
		transaction.commit();
		return std::nullopt;
	}
	const Identity identity = impl_->identityFrom(query.get());
	Statement	   update(impl_->database,
						  "UPDATE api_sessions SET last_used_at = ?1 "
							   "WHERE token_hash = ?2");
	update.bindInteger(1, now);
	update.bindText(2, tokenHash);
	update.execute();
	transaction.commit();
	return identity;
}

void SqliteAuthProvider::revokeSession(std::string_view token) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	if (token.size() != Config::Limits::TOKEN_HEX_LENGTH ||
		!std::all_of(token.begin(), token.end(), [](unsigned char character) {
			return std::isxdigit(character) != 0;
		})) {
		return;
	}
	Statement remove(impl_->database,
					 "DELETE FROM api_sessions WHERE token_hash = ?1");
	remove.bindText(1, Detail::hashSessionToken(token));
	remove.execute();
}

} // namespace Auth
