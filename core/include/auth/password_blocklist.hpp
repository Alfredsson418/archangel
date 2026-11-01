#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Auth {

/**
 * @brief Operator-provided list of passwords that may not be chosen.
 *
 * Entries are compared case-insensitively for ASCII letters, so one entry
 * covers its capitalized variants.
 */
class PasswordBlocklist {
  public:
	/**
	 * @brief Reads a blocklist file with one password per line.
	 *
	 * Empty lines and lines longer than the maximum encoded password size are
	 * ignored; a trailing carriage return is removed from each line.
	 * @param path File that must be a regular, non-symlinked file owned by
	 * root or the service user, not writable by group or others, and no larger
	 * than AppConfigLimits::MAX_PASSWORD_BLOCKLIST_BYTES.
	 * @return The loaded blocklist.
	 * @throws std::runtime_error If the file is unsafe, unreadable, too large,
	 * or contains no entries.
	 */
	static PasswordBlocklist load(const std::string &path);

	/**
	 * @brief Builds a blocklist from file content already in memory.
	 * @param content Newline-separated passwords, parsed as by load().
	 * @return The blocklist, which may be empty.
	 */
	static PasswordBlocklist fromContent(std::string content);

	/**
	 * @brief Checks whether a password is on the list.
	 * @param password Candidate password.
	 * @return True when the password matches an entry.
	 */
	bool contains(std::string_view password) const;

	/**
	 * @brief Reports the number of distinct entries.
	 * @return Entry count.
	 */
	std::size_t size() const;

  private:
	// Entries are views into content_, which never moves once loaded.
	std::shared_ptr<const std::string> content_;
	std::vector<std::string_view>	   entries_;
};

} // namespace Auth
