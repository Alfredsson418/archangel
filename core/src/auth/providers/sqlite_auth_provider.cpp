#include "../../../include/auth/providers/auth_provider.hpp"
#include "../auth_crypto.hpp"
#include "../sqlite_auth_storage.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace Auth {
namespace {
using AuthStorage::Statement;
using AuthStorage::Transaction;
using Auth::Detail::hashPassword;
using Auth::Detail::hashSessionToken;
using Auth::Detail::makeUuid;
using Auth::Detail::normalizeUsername;
using Auth::Detail::verifyPassword;
using Auth::Detail::validatePassword;

constexpr std::uint32_t MAX_ARGON2_MEMORY_KIB = 1024 * 1024;
constexpr std::uint32_t MAX_ARGON2_ITERATIONS = 10;
constexpr std::uint32_t MAX_ARGON2_PARALLELISM = 8;
constexpr std::size_t SESSION_TOKEN_HEX_LENGTH = 64;

Auth::Role parseRole(int role) {
	switch (role) {
	case 0:
		return Auth::Role::Viewer;
	case 1:
		return Auth::Role::Operator;
	case 2:
		return Auth::Role::Administrator;
	default:
		throw std::runtime_error("Authentication database contains invalid role");
	}
}

} // namespace

struct SqliteAuthProvider::Impl {
	explicit Impl(const std::string &path, std::chrono::seconds idle,
				  std::chrono::seconds absolute,
				  PasswordPolicy policy,
				  Argon2idParameters argonParameters)
		: idleTimeout(idle), absoluteTimeout(absolute),
		  passwordPolicy(policy), argon2idParameters(argonParameters) {
		if (idleTimeout <= std::chrono::seconds::zero() ||
			absoluteTimeout <= idleTimeout) {
			throw std::runtime_error("Invalid API session lifetime settings");
		}
		if (passwordPolicy.minimumCharacters < 15 ||
			passwordPolicy.maximumCharacters > 128 ||
			passwordPolicy.minimumCharacters >
				passwordPolicy.maximumCharacters) {
			throw std::runtime_error(
				"Invalid local-account password policy settings");
		}
		if (argon2idParameters.memoryKiB < 19 * 1024 ||
			argon2idParameters.memoryKiB >
				MAX_ARGON2_MEMORY_KIB ||
			argon2idParameters.iterations < 2 ||
			argon2idParameters.iterations > MAX_ARGON2_ITERATIONS ||
			argon2idParameters.parallelism < 1 ||
			argon2idParameters.parallelism > MAX_ARGON2_PARALLELISM ||
			argon2idParameters.memoryKiB <
				argon2idParameters.parallelism * 8) {
			throw std::runtime_error(
				"Invalid Argon2id password hashing settings");
		}
		storage = std::make_unique<AuthStorage::Database>(path);
		database = storage->get();
		dummyPasswordHash =
			hashPassword("archangel-dummy-password-value", argon2idParameters);
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
		return Identity{id, username,
						parseRole(sqlite3_column_int(statement, 2))};
	}

	std::unique_ptr<AuthStorage::Database> storage;
	sqlite3 *database = nullptr;
	std::string			dummyPasswordHash;
	std::chrono::seconds idleTimeout;
	std::chrono::seconds absoluteTimeout;
	PasswordPolicy		 passwordPolicy;
	Argon2idParameters	 argon2idParameters;
	std::mutex			  databaseMutex;
};

SqliteAuthProvider::SqliteAuthProvider(std::string databasePath,
									   std::chrono::seconds idleTimeout,
									   std::chrono::seconds absoluteTimeout,
									   PasswordPolicy passwordPolicy,
									   Argon2idParameters argon2idParameters)
	: impl_(std::make_unique<Impl>(databasePath, idleTimeout,
								   absoluteTimeout, passwordPolicy,
								   argon2idParameters)) {}

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
	const bool passwordTooLong = password.size() > 512;
	const std::string_view boundedPassword =
		passwordTooLong ? password.substr(0, 512) : password;
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
	if (hash == nullptr) {
		throw std::runtime_error(
			"Authentication database contains an invalid password hash");
	}
	const std::string passwordHash(hash);
	const bool enabled = sqlite3_column_int(userQuery.get(), 4) != 0;
	const bool passwordValid = verifyPassword(passwordHash, boundedPassword);
	if (passwordTooLong || !passwordValid || !enabled) {
		return std::nullopt;
	}
	const Identity identity = impl_->identityFrom(userQuery.get());

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count();
	const auto expiry = now + impl_->absoluteTimeout.count();
	const std::string token = Auth::Detail::createSessionToken();
	const std::string tokenHash = Auth::Detail::hashSessionToken(token);
	Transaction transaction(impl_->database);
	{
		Statement removeExpired(
			impl_->database,
			"DELETE FROM api_sessions WHERE expires_at <= ?1 OR "
			"last_used_at <= ?2");
		removeExpired.bindInteger(1, now);
		removeExpired.bindInteger(2, now - impl_->idleTimeout.count());
		removeExpired.execute();
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
	if (token.size() != SESSION_TOKEN_HEX_LENGTH ||
		!std::all_of(token.begin(), token.end(), [](unsigned char character) {
			return std::isxdigit(character) != 0;
		})) {
		return std::nullopt;
	}
	const std::string tokenHash = Auth::Detail::hashSessionToken(token);
	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count();
	Transaction transaction(impl_->database);
	Statement query(
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
		throw std::runtime_error(
			std::string("Unable to query API session: ") +
			sqlite3_errmsg(impl_->database));
	}
	const auto expiry = sqlite3_column_int64(query.get(), 3);
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
	Statement update(impl_->database,
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
	if (token.size() != SESSION_TOKEN_HEX_LENGTH ||
		!std::all_of(token.begin(), token.end(), [](unsigned char character) {
			return std::isxdigit(character) != 0;
		})) {
		return;
	}
	Statement remove(impl_->database,
					 "DELETE FROM api_sessions WHERE token_hash = ?1");
	remove.bindText(1, Auth::Detail::hashSessionToken(token));
	remove.execute();
}

Identity SqliteAuthProvider::bootstrapAdministrator(
	std::string_view username, std::string_view password) {
	if (!impl_) {
		throw std::runtime_error("Authentication provider is not initialized");
	}
	std::lock_guard<std::mutex> lock(impl_->databaseMutex);
	const std::string normalized = normalizeUsername(username);
	if (normalized.empty()) {
		throw std::runtime_error(
			"Username must be 3-64 ASCII letters, digits, dots, underscores, "
			"or hyphens");
	}
	validatePassword(password, impl_->passwordPolicy);
	const std::string passwordHash =
		hashPassword(password, impl_->argon2idParameters);
	const std::string userId = makeUuid();
	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count();

	Transaction transaction(impl_->database);
	{
		Statement activeAdmin(
			impl_->database,
			"SELECT 1 FROM users WHERE role = 2 AND enabled = 1 LIMIT 1");
		const int result = sqlite3_step(activeAdmin.get());
		if (result == SQLITE_ROW) {
			throw std::runtime_error(
				"An active administrator already exists");
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

} // namespace Auth
