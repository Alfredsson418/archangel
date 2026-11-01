#include "sqlite_auth_storage.hpp"

#include <cerrno>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
constexpr int CURRENT_SCHEMA_VERSION = 2;

std::string createPrivateDatabasePath(const std::string &requestedPath) {
	std::filesystem::path path(requestedPath);
	if (path.empty() || path.filename().empty() || path.filename() == "." ||
		path.filename() == "..") {
		throw std::runtime_error("Authentication database path is invalid");
	}
	std::filesystem::path parent = path.parent_path();
	if (parent.empty()) {
		parent = ".";
	}
	const mode_t	previousMask = umask(0077);
	std::error_code error;
	std::filesystem::create_directories(parent, error);
	umask(previousMask);
	if (error) {
		throw std::runtime_error(
			"Unable to create authentication database directory: " +
			error.message());
	}
	parent = std::filesystem::canonical(parent, error);
	if (error) {
		throw std::runtime_error(
			"Unable to resolve authentication database directory: " +
			error.message());
	}
	struct stat directoryInfo {};
	if (lstat(parent.c_str(), &directoryInfo) != 0 ||
		!S_ISDIR(directoryInfo.st_mode) || directoryInfo.st_uid != geteuid() ||
		(directoryInfo.st_mode & 0777) != 0700) {
		throw std::runtime_error(
			"Authentication database directory must be owned by the service "
			"user and have mode 0700");
	}
	path = parent / path.filename();

	struct stat databaseInfo {};
	if (lstat(path.c_str(), &databaseInfo) == 0) {
		if (!S_ISREG(databaseInfo.st_mode) ||
			databaseInfo.st_uid != geteuid() || databaseInfo.st_nlink != 1 ||
			(databaseInfo.st_mode & 0777) != 0600) {
			throw std::runtime_error(
				"Existing authentication database must be a regular file "
				"owned by the service user with mode 0600");
		}
	} else if (errno != ENOENT) {
		throw std::runtime_error(
			"Unable to inspect authentication database path");
	}
	return path.string();
}
} // namespace

namespace AuthStorage {

Statement::Statement(sqlite3 *database, const char *sql) : database_(database) {
	const int result =
		sqlite3_prepare_v2(database_, sql, -1, &statement_, nullptr);
	if (result != SQLITE_OK) {
		throw std::runtime_error(
			std::string("Unable to prepare authentication query: ") +
			sqlite3_errmsg(database_));
	}
}

Statement::~Statement() { sqlite3_finalize(statement_); }

sqlite3_stmt *Statement::get() const { return statement_; }

void Statement::bindText(int index, std::string_view value) {
	const int result =
		sqlite3_bind_text(statement_, index, value.data(),
						  static_cast<int>(value.size()), SQLITE_TRANSIENT);
	if (result != SQLITE_OK) {
		throw std::runtime_error(
			std::string("Unable to bind authentication query: ") +
			sqlite3_errmsg(database_));
	}
}

void Statement::bindInteger(int index, sqlite3_int64 value) {
	const int result = sqlite3_bind_int64(statement_, index, value);
	if (result != SQLITE_OK) {
		throw std::runtime_error(
			std::string("Unable to bind authentication query: ") +
			sqlite3_errmsg(database_));
	}
}

void Statement::execute() {
	const int result = sqlite3_step(statement_);
	if (result != SQLITE_DONE) {
		throw std::runtime_error(std::string("Authentication query failed: ") +
								 sqlite3_errmsg(database_));
	}
}

Transaction::Transaction(sqlite3 *database) : database_(database) {
	executeSql(database_, "BEGIN IMMEDIATE");
}

Transaction::~Transaction() {
	if (!committed_) {
		sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr);
	}
}

void Transaction::commit() {
	executeSql(database_, "COMMIT");
	committed_ = true;
}

void executeSql(sqlite3 *database, const char *sql) {
	char	 *message = nullptr;
	const int result  = sqlite3_exec(database, sql, nullptr, nullptr, &message);
	if (result != SQLITE_OK) {
		const std::string detail =
			message == nullptr ? sqlite3_errmsg(database) : message;
		sqlite3_free(message);
		throw std::runtime_error("Authentication database error: " + detail);
	}
}

Database::Database(const std::string &path) {
	const std::string databasePath = createPrivateDatabasePath(path);
	const int		  flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
					  SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW;
	const int openResult =
		sqlite3_open_v2(databasePath.c_str(), &database_, flags, nullptr);
	if (openResult != SQLITE_OK) {
		const std::string detail = database_ == nullptr
									   ? "unable to allocate SQLite connection"
									   : sqlite3_errmsg(database_);
		if (database_ != nullptr) {
			sqlite3_close(database_);
			database_ = nullptr;
		}
		throw std::runtime_error("Unable to open authentication database: " +
								 detail);
	}
	try {
		if (chmod(databasePath.c_str(), 0600) != 0) {
			throw std::runtime_error(
				"Unable to set authentication database mode 0600");
		}
		sqlite3_busy_timeout(database_, 5000);
		executeSql(database_, "PRAGMA foreign_keys = ON");
		executeSql(database_, "PRAGMA secure_delete = ON");
		migrate();
	} catch (...) {
		sqlite3_close(database_);
		database_ = nullptr;
		throw;
	}
}

Database::~Database() {
	if (database_ != nullptr) {
		sqlite3_close(database_);
	}
}

sqlite3 *Database::get() const { return database_; }

void Database::migrate() {
	int version = 0;
	{
		Statement versionQuery(database_, "PRAGMA user_version");
		if (sqlite3_step(versionQuery.get()) != SQLITE_ROW) {
			throw std::runtime_error(
				"Unable to read authentication database schema version");
		}
		version = sqlite3_column_int(versionQuery.get(), 0);
	}
	if (version > CURRENT_SCHEMA_VERSION) {
		throw std::runtime_error(
			"Authentication database schema is newer than this backend");
	}
	if (version < 0 || version > CURRENT_SCHEMA_VERSION) {
		throw std::runtime_error(
			"Unsupported authentication database schema version");
	}
	if (version == 0) {
		Transaction transaction(database_);
		executeSql(database_,
				   "CREATE TABLE users ("
				   "id TEXT PRIMARY KEY NOT NULL,"
				   "username TEXT NOT NULL,"
				   "normalized_username TEXT NOT NULL UNIQUE,"
				   "role INTEGER NOT NULL CHECK(role IN (0, 1, 2)),"
				   "password_hash TEXT NOT NULL,"
				   "enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),"
				   "created_at INTEGER NOT NULL,"
				   "updated_at INTEGER NOT NULL"
				   ")");
		executeSql(database_, "CREATE TABLE api_sessions ("
							  "token_hash TEXT PRIMARY KEY NOT NULL,"
							  "user_id TEXT NOT NULL REFERENCES users(id),"
							  "created_at INTEGER NOT NULL,"
							  "last_used_at INTEGER NOT NULL,"
							  "expires_at INTEGER NOT NULL"
							  ")");
		executeSql(database_, "CREATE INDEX api_sessions_user_id_idx ON "
							  "api_sessions(user_id)");
		executeSql(database_, "PRAGMA user_version = 1");
		transaction.commit();
		version = 1;
	}
	if (version == 1) {
		Transaction transaction(database_);
		executeSql(
			database_,
			"ALTER TABLE users ADD COLUMN setup_pending INTEGER NOT NULL "
			"DEFAULT 0 CHECK(setup_pending IN (0, 1))");
		executeSql(database_, "CREATE TABLE account_setup_tokens ("
							  "token_hash TEXT PRIMARY KEY NOT NULL,"
							  "user_id TEXT NOT NULL REFERENCES users(id),"
							  "created_at INTEGER NOT NULL,"
							  "expires_at INTEGER NOT NULL"
							  ")");
		executeSql(database_,
				   "CREATE INDEX account_setup_tokens_user_id_idx ON "
				   "account_setup_tokens(user_id)");
		executeSql(database_, "PRAGMA user_version = 2");
		transaction.commit();
		version = 2;
	}
	if (version != CURRENT_SCHEMA_VERSION) {
		throw std::runtime_error(
			"Unsupported authentication database schema version");
	}
}

} // namespace AuthStorage
