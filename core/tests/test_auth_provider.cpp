#include "auth/providers/sqlite_auth_provider.hpp"
#include "test_support.hpp"

#include <sqlite3.h>

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
class TemporaryDirectory {
  public:
	TemporaryDirectory() {
		std::string		  pattern = "/tmp/archangel-auth-test-XXXXXX";
		std::vector<char> writable(pattern.begin(), pattern.end());
		writable.push_back('\0');
		const char *created = mkdtemp(writable.data());
		if (created == nullptr) {
			throw std::runtime_error(
				"Unable to create authentication test directory");
		}
		path_ = created;
	}

	~TemporaryDirectory() {
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	const std::filesystem::path &path() const { return path_; }

  private:
	std::filesystem::path path_;
};

std::string readFile(const std::filesystem::path &path) {
	std::ifstream input(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(input),
					   std::istreambuf_iterator<char>());
}

std::string sessionTokenHash(const std::string &token) {
	std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
	unsigned int							   digestLength = 0;
	if (EVP_Digest(token.data(), token.size(), digest.data(), &digestLength,
				   EVP_sha256(), nullptr) != 1) {
		throw std::runtime_error("Unable to hash test session token");
	}
	std::string			  encoded;
	static constexpr char digits[] = "0123456789abcdef";
	for (unsigned int index = 0; index < digestLength; ++index) {
		encoded.push_back(digits[digest[index] >> 4]);
		encoded.push_back(digits[digest[index] & 0x0f]);
	}
	return encoded;
}

void bootstrapsAdminAndCreatesHashedSessions() {
	TemporaryDirectory		 directory;
	const auto				 database = directory.path() / "archangel.db";
	Auth::SqliteAuthProvider provider(database.string());

	const Auth::Identity created = provider.bootstrapAdministrator(
		"Initial.Admin", "a sufficiently long passphrase");
	TestSupport::require(created.username == "initial.admin",
						 "usernames should be stored in normalized form");
	TestSupport::require(created.role == Auth::Role::Administrator,
						 "bootstrap should grant the administrator role");
	TestSupport::require(created.id.size() == 36,
						 "account IDs should be UUID-shaped");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			provider.bootstrapAdministrator(
				"second-admin", "another sufficiently long passphrase");
		},
		"bootstrap must refuse when an active administrator already exists");

	TestSupport::require(!provider.login("INITIAL.ADMIN", "wrong passphrase"),
						 "incorrect passwords must not authenticate");
	TestSupport::require(
		!provider.login("unknown-user", "another sufficiently long passphrase"),
		"unknown users must not authenticate");
	const auto session =
		provider.login("INITIAL.ADMIN", "a sufficiently long passphrase");
	TestSupport::require(
		session.has_value(),
		"valid case-insensitive credentials should authenticate");
	TestSupport::require(session->token.size() == 64,
						 "session tokens should contain 256 random bits");
	TestSupport::require(session->identity.id == created.id,
						 "login should return the immutable account identity");

	const std::string databaseContents = readFile(database);
	TestSupport::require(databaseContents.find(session->token) ==
							 std::string::npos,
						 "database must not contain the raw session token");
	TestSupport::require(databaseContents.find(sessionTokenHash(
							 session->token)) != std::string::npos,
						 "database should contain only the SHA-256 token hash");
	TestSupport::require(
		databaseContents.find("a sufficiently long passphrase") ==
			std::string::npos,
		"database must not contain plaintext passwords");
	const auto authenticated = provider.authenticateSession(session->token);
	TestSupport::require(authenticated.has_value() &&
							 authenticated->id == created.id,
						 "valid session tokens should resolve to their user");
	provider.revokeSession(session->token);
	TestSupport::require(
		!provider.authenticateSession(session->token),
		"revoked session tokens should no longer authenticate");

	struct stat databaseInfo {};
	TestSupport::require(stat(database.c_str(), &databaseInfo) == 0 &&
							 (databaseInfo.st_mode & 0777) == 0600,
						 "database files should have mode 0600");
	struct stat directoryInfo {};
	TestSupport::require(
		stat(directory.path().c_str(), &directoryInfo) == 0 &&
			(directoryInfo.st_mode & 0777) == 0700,
		"authentication database directory should have mode 0700");
}

void enforcesPasswordAndUsernamePolicy() {
	TemporaryDirectory		 directory;
	Auth::SqliteAuthProvider provider(
		(directory.path() / "archangel.db").string());
	TestSupport::requireThrows<std::runtime_error>(
		[&] { provider.bootstrapAdministrator("ab", "long enough password"); },
		"usernames shorter than three characters must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[&] { provider.bootstrapAdministrator("valid-user", "too short"); },
		"passwords shorter than fifteen characters must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[&] { provider.bootstrapAdministrator("valid-user", "ééééééé"); },
		"password minimum must count Unicode code points");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			provider.bootstrapAdministrator("valid-user",
											std::string(129, 'x'));
		},
		"passwords longer than 128 characters must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			provider.bootstrapAdministrator("invalid/name",
											"long enough password");
		},
		"unsupported username characters must be rejected");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			provider.bootstrapAdministrator("usérname", "long enough password");
		},
		"non-ASCII usernames must be rejected");
}

void appliesConfiguredPasswordAndArgonParameters() {
	TemporaryDirectory		 directory;
	Auth::SqliteAuthProvider provider(
		(directory.path() / "configured.db").string(), std::chrono::minutes(15),
		std::chrono::hours(8), Auth::PasswordPolicy{16, 80},
		Auth::Argon2idParameters{20 * 1024, 3, 1});
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			provider.bootstrapAdministrator("configured-admin",
											"short password!");
		},
		"configured password minimums should be enforced");
	const auto identity = provider.bootstrapAdministrator(
		"configured-admin", "a sufficiently long configured passphrase");
	TestSupport::require(provider
							 .login("configured-admin",
									"a sufficiently long configured passphrase")
							 .has_value(),
						 "configured Argon2id hashes should remain verifiable");
	TestSupport::require(
		identity.role == Auth::Role::Administrator,
		"configured bootstrap should retain administrator role");
}

void rejectsUnsafeDatabaseFiles() {
	TemporaryDirectory directory;
	const auto		   database = directory.path() / "unsafe.db";
	{
		std::ofstream output(database);
		output << "not a database";
	}
	chmod(database.c_str(), 0644);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Auth::SqliteAuthProvider provider(database.string()); },
		"existing databases with group/world permissions must be rejected");

	const auto symlink = directory.path() / "linked.db";
	std::filesystem::create_symlink(database, symlink);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Auth::SqliteAuthProvider provider(symlink.string()); },
		"database symlinks must be rejected");

	const auto unsafeDirectory = directory.path() / "unsafe-directory";
	std::filesystem::create_directory(unsafeDirectory);
	chmod(unsafeDirectory.c_str(), 0755);
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			Auth::SqliteAuthProvider provider(
				(unsafeDirectory / "auth.db").string());
		},
		"database directories with group/world permissions must be rejected");
}

void expiresIdleSessions() {
	TemporaryDirectory		 directory;
	Auth::SqliteAuthProvider provider(
		(directory.path() / "archangel.db").string(), std::chrono::seconds(1),
		std::chrono::seconds(4));
	provider.bootstrapAdministrator("initial-admin",
									"a sufficiently long passphrase");
	const auto session =
		provider.login("initial-admin", "a sufficiently long passphrase");
	TestSupport::require(session.has_value(),
						 "administrator should be able to create a session");
	std::this_thread::sleep_for(std::chrono::milliseconds(1100));
	TestSupport::require(!provider.authenticateSession(session->token),
						 "idle sessions should expire after inactivity");
}

void managesAccountsAndOneTimeSetupTokens() {
	TemporaryDirectory		 directory;
	Auth::SqliteAuthProvider provider(
		(directory.path() / "accounts.db").string());
	const Auth::Identity administrator = provider.bootstrapAdministrator(
		"first-admin", "first administrator secure passphrase");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] { provider.disableAccount(administrator.id); },
		"the final active administrator cannot be disabled");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.updateAccount(
				administrator.id,
				Auth::AccountUpdate{std::nullopt, Auth::Role::Operator});
		},
		"the final active administrator cannot be demoted");

	const Auth::AccountSetup created =
		provider.createAccount("Operator.One", Auth::Role::Operator);
	TestSupport::require(created.account.setup_pending &&
							 !created.account.enabled &&
							 created.setup_token.size() == 64,
						 "new accounts should be disabled and pending setup");
	TestSupport::require(
		!provider.login("operator.one", "operator account secure passphrase"),
		"pending accounts must not authenticate");
	const auto pendingAccounts = provider.listAccounts();
	TestSupport::require(pendingAccounts.size() == 2,
						 "account listing should include pending accounts");

	const Auth::Identity operatorIdentity = provider.completeAccountSetup(
		created.setup_token, "operator account secure passphrase");
	TestSupport::require(operatorIdentity.username == "operator.one",
						 "setup should return the normalized account");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.completeAccountSetup(created.setup_token,
										  "another operator secure passphrase");
		},
		"setup tokens should be single use");
	const auto operatorSession =
		provider.login("operator.one", "operator account secure passphrase");
	TestSupport::require(operatorSession.has_value(),
						 "completed accounts should be able to log in");

	const Auth::Account updated = provider.updateAccount(
		operatorIdentity.id,
		Auth::AccountUpdate{std::string("new-operator"), Auth::Role::Viewer});
	TestSupport::require(
		updated.identity.username == "new-operator" &&
			updated.identity.role == Auth::Role::Viewer &&
			!provider.authenticateSession(operatorSession->token),
		"updates should preserve IDs and revoke existing sessions");

	const Auth::AccountSetup reset =
		provider.issueAccountSetupToken(operatorIdentity.id);
	TestSupport::require(
		!provider.authenticateSession(operatorSession->token),
		"password reset initiation should revoke existing API sessions");
	provider.completeAccountSetup(reset.setup_token,
								  "updated operator secure passphrase");
	TestSupport::require(
		!provider.login("new-operator", "operator account secure passphrase") &&
			provider.login("new-operator", "updated operator secure passphrase")
				.has_value(),
		"reset token redemption should replace the account password");

	const auto secondAdmin =
		provider.createAccount("second-admin", Auth::Role::Administrator);
	provider.completeAccountSetup(secondAdmin.setup_token,
								  "second administrator secure passphrase");
	provider.disableAccount(administrator.id);
	provider.disableAccount(operatorIdentity.id);
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] { provider.createAccount("FIRST-ADMIN", Auth::Role::Viewer); },
		"disabled usernames must not be reused");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.updateAccount(operatorIdentity.id, Auth::AccountUpdate{});
		},
		"empty account updates must be rejected");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] { provider.issueAccountSetupToken(operatorIdentity.id); },
		"disabled accounts must not receive setup tokens");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] { provider.disableAccount(secondAdmin.account.identity.id); },
		"the final active administrator cannot be disabled");
}
std::string storedPasswordHash(const std::filesystem::path &database,
							   const std::string		   &username) {
	sqlite3 *connection = nullptr;
	if (sqlite3_open_v2(database.c_str(), &connection, SQLITE_OPEN_READONLY,
						nullptr) != SQLITE_OK) {
		sqlite3_close(connection);
		throw std::runtime_error("Unable to open test database");
	}
	sqlite3_stmt *statement = nullptr;
	sqlite3_prepare_v2(connection,
					   "SELECT password_hash FROM users WHERE username = ?1",
					   -1, &statement, nullptr);
	sqlite3_bind_text(statement, 1, username.c_str(), -1, SQLITE_TRANSIENT);
	std::string hash;
	if (sqlite3_step(statement) == SQLITE_ROW) {
		hash =
			reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
	}
	sqlite3_finalize(statement);
	sqlite3_close(connection);
	return hash;
}

void recoversAdministratorAccess() {
	TemporaryDirectory		 directory;
	Auth::SqliteAuthProvider provider(
		(directory.path() / "recover.db").string());
	const Auth::Identity first = provider.bootstrapAdministrator(
		"first-admin", "first administrator secure passphrase");
	const auto second =
		provider.createAccount("second-admin", Auth::Role::Administrator);
	provider.completeAccountSetup(second.setup_token,
								  "second administrator secure passphrase");
	const auto viewer = provider.createAccount("viewer", Auth::Role::Viewer);
	provider.completeAccountSetup(viewer.setup_token,
								  "viewer account secure passphrase");
	const auto viewerSession =
		provider.login("viewer", "viewer account secure passphrase");
	provider.disableAccount(first.id);

	const Auth::Identity recovered = provider.recoverAdministrator(
		"FIRST-ADMIN", "recovered administrator passphrase");
	TestSupport::require(recovered.id == first.id &&
							 recovered.username == "first-admin" &&
							 recovered.role == Auth::Role::Administrator,
						 "recovery should keep the account's immutable ID");
	TestSupport::require(
		!provider.login("first-admin", "first administrator secure passphrase"),
		"recovery should replace the previous password");
	TestSupport::require(
		provider.login("first-admin", "recovered administrator passphrase")
			.has_value(),
		"recovery should re-enable a disabled account with the new password");

	const Auth::Identity promoted = provider.recoverAdministrator(
		"viewer", "promoted viewer secure passphrase");
	TestSupport::require(promoted.role == Auth::Role::Administrator,
						 "recovery should grant the administrator role");
	TestSupport::require(
		viewerSession.has_value() &&
			!provider.authenticateSession(viewerSession->token),
		"recovery should revoke the account's sessions");

	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.recoverAdministrator("missing-user",
										  "recovered administrator passphrase");
		},
		"recovery should refuse unknown accounts");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] { provider.recoverAdministrator("first-admin", "too short"); },
		"recovery should enforce the password policy");
}

void rehashesPasswordsWhenArgonCostIncreases() {
	TemporaryDirectory directory;
	const auto		   database = directory.path() / "rehash.db";
	{
		Auth::SqliteAuthProvider baseline(database.string());
		baseline.bootstrapAdministrator("rehash-admin",
										"a sufficiently long passphrase");
	}
	TestSupport::require(storedPasswordHash(database, "rehash-admin")
								 .rfind("$argon2id$v=19$m=19456,t=2,p=1$", 0) ==
							 0,
						 "bootstrap should use the baseline Argon2id cost");

	Auth::SqliteAuthProvider stronger(
		database.string(), std::chrono::minutes(15), std::chrono::hours(8),
		Auth::PasswordPolicy{}, Auth::Argon2idParameters{20 * 1024, 3, 1});
	TestSupport::require(
		!stronger.login("rehash-admin", "wrong passphrase value"),
		"failed logins should not authenticate");
	TestSupport::require(storedPasswordHash(database, "rehash-admin")
								 .rfind("$argon2id$v=19$m=19456,t=2,p=1$", 0) ==
							 0,
						 "failed logins must not rehash the password");
	TestSupport::require(
		stronger.login("rehash-admin", "a sufficiently long passphrase")
			.has_value(),
		"hashes made at a lower cost should still verify");
	const std::string upgraded = storedPasswordHash(database, "rehash-admin");
	TestSupport::require(
		upgraded.rfind("$argon2id$v=19$m=20480,t=3,p=1$", 0) == 0,
		"a successful login should rehash at the configured cost");
	TestSupport::require(
		stronger.login("rehash-admin", "a sufficiently long passphrase")
			.has_value(),
		"the upgraded hash should verify");
	TestSupport::require(
		storedPasswordHash(database, "rehash-admin") == upgraded,
		"hashes at the configured cost should not be rehashed");
}

void rejectsBlocklistedPasswords() {
	const Auth::PasswordBlocklist parsed = Auth::PasswordBlocklist::fromContent(
		"Correct Horse Battery Staple\r\n\nletmein-letmein-letmein\n"
		"letmein-letmein-letmein\n" +
		std::string(AppConfigLimits::MAX_PASSWORD_BYTES + 1, 'x'));
	TestSupport::require(
		parsed.size() == 2,
		"blocklists should skip empty, duplicate, and oversized "
		"lines");
	TestSupport::require(parsed.contains("correct horse battery staple") &&
							 parsed.contains("CORRECT HORSE BATTERY STAPLE"),
						 "blocklist matches should ignore ASCII case");
	TestSupport::require(!parsed.contains("correct horse battery"),
						 "blocklist matches should be exact");

	TemporaryDirectory directory;
	const auto		   listPath = directory.path() / "blocked.txt";
	{
		std::ofstream output(listPath);
		output << "Correct Horse Battery Staple\n";
	}
	chmod(listPath.c_str(), 0644);
	TestSupport::require(Auth::PasswordBlocklist::load(listPath.string())
							 .contains("correct horse battery staple"),
						 "readable private blocklists should load");
	chmod(listPath.c_str(), 0664);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Auth::PasswordBlocklist::load(listPath.string()); },
		"group-writable blocklists must be rejected");
	chmod(listPath.c_str(), 0644);
	const auto linkPath = directory.path() / "linked.txt";
	std::filesystem::create_symlink(listPath, linkPath);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Auth::PasswordBlocklist::load(linkPath.string()); },
		"blocklist symlinks must be rejected");
	const auto emptyPath = directory.path() / "empty.txt";
	{
		std::ofstream output(emptyPath);
		output << "\n\n";
	}
	TestSupport::requireThrows<std::runtime_error>(
		[&] { Auth::PasswordBlocklist::load(emptyPath.string()); },
		"blocklists without entries must be rejected");

	Auth::PasswordPolicy policy;
	policy.blocklist = std::make_shared<const Auth::PasswordBlocklist>(parsed);
	Auth::SqliteAuthProvider provider(
		(directory.path() / "blocked.db").string(), std::chrono::minutes(15),
		std::chrono::hours(8), policy);
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.bootstrapAdministrator("blocked-admin",
											"Correct Horse Battery Staple");
		},
		"bootstrap should reject blocklisted passwords");
	provider.bootstrapAdministrator("blocked-admin",
									"an unlisted secure passphrase");
	const auto pending = provider.createAccount("pending", Auth::Role::Viewer);
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.completeAccountSetup(pending.setup_token,
										  "letmein-letmein-letmein");
		},
		"account setup should reject blocklisted passwords");
	provider.completeAccountSetup(pending.setup_token,
								  "another unlisted secure passphrase");
	TestSupport::requireThrows<Auth::AccountOperationError>(
		[&] {
			provider.recoverAdministrator("pending",
										  "correct horse battery staple");
		},
		"recovery should reject blocklisted passwords");
}
} // namespace

void runAuthProviderTests() {
	bootstrapsAdminAndCreatesHashedSessions();
	enforcesPasswordAndUsernamePolicy();
	appliesConfiguredPasswordAndArgonParameters();
	rejectsUnsafeDatabaseFiles();
	expiresIdleSessions();
	managesAccountsAndOneTimeSetupTokens();
	recoversAdministratorAccess();
	rehashesPasswordsWhenArgonCostIncreases();
	rejectsBlocklistedPasswords();
}
