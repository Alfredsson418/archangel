#pragma once

#include "auth/auth_provider.hpp"
#include "auth/password_blocklist.hpp"
#include "config/app_config.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace Auth {

// Local-account password policy and hashing settings; providers that delegate
// credentials elsewhere, such as a future OIDC provider, do not use them.
struct PasswordPolicy {
	std::uint16_t minimumCharacters = Config::Limits::MIN_PASSWORD_LENGTH;
	std::uint16_t maximumCharacters = Config::Limits::MAX_PASSWORD_LENGTH;
	// Optional list of passwords that may not be chosen; null disables it.
	std::shared_ptr<const PasswordBlocklist> blocklist;
};

struct Argon2idParameters {
	std::uint32_t memoryKiB	  = Config::Limits::MIN_ARGON2ID_MEMORY_KIB;
	std::uint32_t iterations  = Config::Limits::MIN_ARGON2ID_ITERATIONS;
	std::uint32_t parallelism = Config::Limits::MIN_ARGON2ID_PARALLELISM;
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
									Config::Defaults::SESSION_IDLE_TIMEOUT,
								std::chrono::seconds absoluteTimeout =
									Config::Defaults::SESSION_ABSOLUTE_TIMEOUT,
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

	/**
	 * @brief Restores administrator access to an existing local account.
	 *
	 * Sets the password, makes the account an enabled administrator, and
	 * revokes its sessions and setup tokens. Bypasses the last-administrator
	 * safeguards that apply to API account changes.
	 * @param username Existing account name.
	 * @param password New password meeting the configured policy.
	 * @return The recovered administrator identity.
	 * @throws AccountOperationError If the account does not exist or the
	 * username or password is invalid.
	 * @throws std::runtime_error If persistent storage fails.
	 */
	Identity recoverAdministrator(std::string_view username,
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
