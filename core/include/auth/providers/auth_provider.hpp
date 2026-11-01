#pragma once

#include "config/app_config.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace Auth {

enum class Role { Viewer, Operator, Administrator };

struct PasswordPolicy {
	std::uint16_t minimumCharacters = AppConfigLimits::MIN_PASSWORD_LENGTH;
	std::uint16_t maximumCharacters = AppConfigLimits::MAX_PASSWORD_LENGTH;
};

struct Argon2idParameters {
	std::uint32_t memoryKiB	  = AppConfigLimits::MIN_ARGON2ID_MEMORY_KIB;
	std::uint32_t iterations  = AppConfigLimits::MIN_ARGON2ID_ITERATIONS;
	std::uint32_t parallelism = AppConfigLimits::MIN_ARGON2ID_PARALLELISM;
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

struct Account {
	Identity identity;
	bool	 enabled	   = false;
	bool	 setup_pending = false;
};

struct AccountSetup {
	Account		account;
	std::string setup_token;
};

struct AccountUpdate {
	std::optional<std::string> username;
	std::optional<Role>		   role;
};

class AccountOperationError : public std::runtime_error {
  public:
	enum class Code {
		Invalid,
		NotFound,
		Conflict,
		LastAdministrator,
		InvalidToken
	};

	AccountOperationError(Code code, const std::string &message)
		: std::runtime_error(message), code(code) {}

	Code code;
};

/**
 * @brief Defines backend-owned credential authentication and API-session
 * behavior.
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

	/**
	 * @brief Lists backend-owned accounts without returning credential data.
	 * @return Account identities, roles, and enabled/setup status.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	virtual std::vector<Account> listAccounts() = 0;

	/**
	 * @brief Creates a pending account and a one-time setup token.
	 * @param username Account name using the local username policy.
	 * @param role Initial account role.
	 * @return The pending account and plaintext setup token, returned once.
	 * @throws AccountOperationError If the account name is invalid or in use.
	 * @throws std::runtime_error If persistent authentication storage fails.
	 */
	virtual AccountSetup createAccount(std::string_view username,
									   Role				role) = 0;

	/**
	 * @brief Updates an account's username and/or role without changing its ID.
	 * @param id Immutable account UUID.
	 * @param update Fields to change; at least one must be present.
	 * @return The updated account.
	 * @throws AccountOperationError If the account is missing, invalid, or the
	 * change would remove the last active administrator.
	 */
	virtual Account updateAccount(std::string_view	   id,
								  const AccountUpdate &update) = 0;

	/**
	 * @brief Disables an account and revokes its sessions.
	 * @param id Immutable account UUID.
	 * @return No value.
	 * @throws AccountOperationError If the account is missing or is the last
	 * active administrator.
	 */
	virtual void disableAccount(std::string_view id) = 0;

	/**
	 * @brief Issues a one-hour setup or password-reset token.
	 * @param id Immutable account UUID.
	 * @return Account metadata and the one-time plaintext setup token.
	 * @throws AccountOperationError If the account is missing or disabled.
	 */
	virtual AccountSetup issueAccountSetupToken(std::string_view id) = 0;

	/**
	 * @brief Sets an account password using a valid setup/reset token.
	 * @param token One-time token returned by account creation or reset.
	 * @param password New password meeting the configured policy.
	 * @return The enabled account identity.
	 * @throws AccountOperationError If the token is invalid, expired, or for a
	 * disabled account.
	 */
	virtual Identity completeAccountSetup(std::string_view token,
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
	explicit SqliteAuthProvider(std::string			 databasePath,
								std::chrono::seconds idleTimeout =
									AppConfigDefaults::SESSION_IDLE_TIMEOUT,
								std::chrono::seconds absoluteTimeout =
									AppConfigDefaults::SESSION_ABSOLUTE_TIMEOUT,
								PasswordPolicy	   passwordPolicy	  = {},
								Argon2idParameters argon2idParameters = {});

	~SqliteAuthProvider() override;

	SqliteAuthProvider(const SqliteAuthProvider &)			  = delete;
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

	std::vector<Account> listAccounts() override;
	AccountSetup createAccount(std::string_view username, Role role) override;
	Account		 updateAccount(std::string_view		id,
							   const AccountUpdate &update) override;
	void		 disableAccount(std::string_view id) override;
	AccountSetup issueAccountSetupToken(std::string_view id) override;
	Identity	 completeAccountSetup(std::string_view token,
									  std::string_view password) override;

  private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace Auth
