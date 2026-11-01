#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Auth {

enum class Role { Viewer, Operator, Administrator };

struct PasswordPolicy {
	std::uint16_t minimumCharacters = 15;
	std::uint16_t maximumCharacters = 128;
};

struct Argon2idParameters {
	std::uint32_t memoryKiB = 19 * 1024;
	std::uint32_t iterations = 2;
	std::uint32_t parallelism = 1;
};

struct Identity {
	std::string id;
	std::string username;
	Role		role;
};

struct Session {
	std::string token;
	Identity	identity;
};

/**
 * @brief Defines backend-owned credential authentication and API-session behavior.
 */
class AuthProvider {
  public:
	virtual ~AuthProvider() = default;

	/**
	 * @brief Verifies local credentials and creates an opaque API session.
	 * @param username Normalized or user-entered account name.
	 * @param password Account password.
	 * @return A one-time session token and the authenticated identity, or no
	 * value when credentials are invalid or the account is disabled.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	virtual std::optional<Session> login(std::string_view username,
										 std::string_view password) = 0;

	/**
	 * @brief Validates and refreshes an API session within its lifetime limits.
	 * @param token Opaque API session token returned by login.
	 * @return The authenticated identity, or no value for an invalid or expired
	 * session.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	virtual std::optional<Identity>
	authenticateSession(std::string_view token) = 0;

	/**
	 * @brief Revokes an API session.
	 * @param token Opaque API session token returned by login.
	 * @return No value.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	virtual void revokeSession(std::string_view token) = 0;

	/**
	 * @brief Creates the initial administrator if none is currently enabled.
	 * @param username Valid account name using ASCII letters, digits, dot,
	 * underscore, or hyphen.
	 * @param password Password meeting the configured local-account policy.
	 * @return The new immutable administrator identity.
	 * @throws std::runtime_error If an administrator already exists, input is
	 * invalid, or persistent storage fails.
	 */
	virtual Identity bootstrapAdministrator(std::string_view username,
											std::string_view password) = 0;
};

/**
 * @brief SQLite-backed local authentication provider using Argon2id hashes.
 */
class SqliteAuthProvider final : public AuthProvider {
  public:
	/**
	 * @brief Opens or initializes a private SQLite account and session store.
	 * @param databasePath SQLite file path; its parent must be owned by the
	 * effective user and have mode 0700, and the database must have mode 0600.
	 * @param idleTimeout Maximum inactivity duration for a session.
	 * @param absoluteTimeout Maximum lifetime of a session regardless of use.
	 * @throws std::runtime_error If the path is unsafe, a migration fails, or
	 * the database cannot be opened.
	 */
	explicit SqliteAuthProvider(
		std::string databasePath,
		std::chrono::seconds idleTimeout = std::chrono::minutes(15),
		std::chrono::seconds absoluteTimeout = std::chrono::hours(8),
		PasswordPolicy passwordPolicy = {},
		Argon2idParameters argon2idParameters = {});

	~SqliteAuthProvider() override;

	SqliteAuthProvider(const SqliteAuthProvider &)			 = delete;
	SqliteAuthProvider &operator=(const SqliteAuthProvider &) = delete;
	SqliteAuthProvider(SqliteAuthProvider &&) noexcept;
	SqliteAuthProvider &operator=(SqliteAuthProvider &&) noexcept;

	/**
	 * @brief Verifies local credentials and creates an opaque API session.
	 * @param username Normalized or user-entered account name.
	 * @param password Account password.
	 * @return A one-time session token and the authenticated identity, or no
	 * value when credentials are invalid or the account is disabled.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	std::optional<Session> login(std::string_view username,
								 std::string_view password) override;

	/**
	 * @brief Validates and refreshes an API session within its lifetime limits.
	 * @param token Opaque API session token returned by login.
	 * @return The authenticated identity, or no value for an invalid or expired
	 * session.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	std::optional<Identity>
	authenticateSession(std::string_view token) override;

	/**
	 * @brief Revokes an API session.
	 * @param token Opaque API session token returned by login.
	 * @return No value.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	void revokeSession(std::string_view token) override;

	/**
	 * @brief Creates the initial administrator if none is currently enabled.
	 * @param username Valid account name using ASCII letters, digits, dot,
	 * underscore, or hyphen.
	 * @param password Password meeting the configured local-account policy.
	 * @return The new immutable administrator identity.
	 * @throws std::runtime_error If an administrator already exists, input is
	 * invalid, or persistent storage fails.
	 */
	Identity bootstrapAdministrator(std::string_view username,
									std::string_view password) override;

  private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace Auth
