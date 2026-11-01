#pragma once

#include <string>

namespace Auth {

/**
 * @brief Holds a secret string and clears its contents when destroyed.
 */
class SecretString {
  public:
	/**
	 * @brief Takes ownership of a secret string.
	 * @param value Secret text to protect for this object's lifetime.
	 * @return No value.
	 */
	explicit SecretString(std::string value);

	/**
	 * @brief Clears the held secret before releasing its storage.
	 * @return No value.
	 */
	~SecretString();

	SecretString(const SecretString &)			  = delete;
	SecretString &operator=(const SecretString &) = delete;

	/**
	 * @brief Provides read-only access to the held secret.
	 * @return The secret string reference.
	 */
	const std::string &value() const;

  private:
	std::string value_;
};

/**
 * @brief Reads a password from the controlling terminal without echo.
 * @param prompt Text to display before reading the password.
 * @return The entered password, limited to Config::Limits::MAX_PASSWORD_BYTES
 * bytes.
 * @throws std::runtime_error If no terminal is available, terminal setup or
 * I/O fails, or the input exceeds the limit.
 */
std::string promptPassword(const char *prompt);

} // namespace Auth
