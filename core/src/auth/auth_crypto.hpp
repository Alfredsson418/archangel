#pragma once

#include "auth/providers/auth_provider.hpp"

#include <string>
#include <string_view>

namespace Auth::Detail {

/**
 * @brief Normalizes an account name or returns an empty value if invalid.
 * @param username Account name supplied by the caller.
 * @return Lowercase ASCII account name, or an empty string if invalid.
 */
std::string normalizeUsername(std::string_view username);

/**
 * @brief Validates a password against the configured code-point policy.
 * @param password Password text to validate.
 * @param policy Accepted minimum and maximum character counts.
 * @return No value.
 * @throws std::runtime_error If encoding, size, or policy validation fails.
 */
void validatePassword(std::string_view password, const PasswordPolicy &policy);

/**
 * @brief Creates a salted Argon2id password hash.
 * @param password Plaintext password.
 * @param parameters Argon2id parameters.
 * @return Encoded Argon2id hash.
 * @throws std::runtime_error If secure randomness or hashing fails.
 */
std::string hashPassword(std::string_view		   password,
						 const Argon2idParameters &parameters);

/**
 * @brief Verifies a password against an encoded Argon2id hash.
 * @param encoded Encoded Argon2id hash.
 * @param password Candidate password.
 * @return True when the password matches the hash.
 * @throws std::runtime_error If the encoded hash cannot be verified.
 */
bool verifyPassword(std::string_view encoded, std::string_view password);

/**
 * @brief Creates a cryptographically random opaque API session token.
 * @return A 256-bit token encoded as lowercase hexadecimal.
 * @throws std::runtime_error If secure random generation fails.
 */
std::string createSessionToken();

/**
 * @brief Hashes a session token before persistent storage.
 * @param token Opaque session token.
 * @return Lowercase hexadecimal SHA-256 digest.
 * @throws std::runtime_error If digest generation fails.
 */
std::string hashSessionToken(std::string_view token);

/**
 * @brief Creates an immutable random UUID account identifier.
 * @return A version 4 UUID.
 * @throws std::runtime_error If secure random generation fails.
 */
std::string makeUuid();

} // namespace Auth::Detail
