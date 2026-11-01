#pragma once

#include "auth/providers/auth_provider.hpp"
#include "config/app_config.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace Auth {

// Local-account password policy and hashing settings; providers that delegate
// credentials elsewhere, such as a future OIDC provider, do not use them.
struct PasswordPolicy {
	std::uint16_t minimumCharacters = AppConfigLimits::MIN_PASSWORD_LENGTH;
	std::uint16_t maximumCharacters = AppConfigLimits::MAX_PASSWORD_LENGTH;
};

struct Argon2idParameters {
	std::uint32_t memoryKiB	  = AppConfigLimits::MIN_ARGON2ID_MEMORY_KIB;
	std::uint32_t iterations  = AppConfigLimits::MIN_ARGON2ID_ITERATIONS;
	std::uint32_t parallelism = AppConfigLimits::MIN_ARGON2ID_PARALLELISM;
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
