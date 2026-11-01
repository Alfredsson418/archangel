#pragma once

#include <sqlite3.h>

#include <string>
#include <string_view>

namespace AuthStorage {

class Statement {
  public:
	Statement(sqlite3 *database, const char *sql);
	~Statement();

	Statement(const Statement &) = delete;
	Statement &operator=(const Statement &) = delete;

	sqlite3_stmt *get() const;
	void bindText(int index, std::string_view value);
	void bindInteger(int index, sqlite3_int64 value);
	void execute();

  private:
	sqlite3 *database_;
	sqlite3_stmt *statement_ = nullptr;
};

class Transaction {
  public:
	explicit Transaction(sqlite3 *database);
	~Transaction();

	Transaction(const Transaction &) = delete;
	Transaction &operator=(const Transaction &) = delete;

	void commit();

  private:
	sqlite3 *database_;
	bool committed_ = false;
};

/**
 * @brief Owns the private SQLite database connection and schema migration.
 */
class Database {
  public:
	explicit Database(const std::string &path);
	~Database();

	Database(const Database &) = delete;
	Database &operator=(const Database &) = delete;

	sqlite3 *get() const;

  private:
	void migrate();

	sqlite3 *database_ = nullptr;
};

void executeSql(sqlite3 *database, const char *sql);

} // namespace AuthStorage
