#include "auth_crypto.hpp"
#include "config/app_config.hpp"

#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
constexpr std::size_t ARGON2_SALT_BYTES = 16;
constexpr std::size_t ARGON2_HASH_BYTES = 32;

std::string hexEncode(const unsigned char *data, std::size_t size) {
	std::ostringstream encoded;
	encoded << std::hex << std::setfill('0');
	for (std::size_t index = 0; index < size; ++index) {
		encoded << std::setw(2) << static_cast<unsigned int>(data[index]);
	}
	return encoded.str();
}

template <std::size_t Size>
std::array<unsigned char, Size> secureRandomBytes() {
	std::array<unsigned char, Size> bytes{};
	if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
		throw std::runtime_error(
			"Cryptographically secure random generation failed");
	}
	return bytes;
}

std::size_t passwordCodepoints(std::string_view password) {
	std::size_t count = 0;
	for (std::size_t index = 0; index < password.size(); ++count) {
		const unsigned char lead = static_cast<unsigned char>(password[index]);
		std::size_t			continuationCount = 0;
		if (lead <= 0x7f) {
			continuationCount = 0;
		} else if (lead >= 0xc2 && lead <= 0xdf) {
			continuationCount = 1;
		} else if (lead >= 0xe0 && lead <= 0xef) {
			continuationCount = 2;
		} else if (lead >= 0xf0 && lead <= 0xf4) {
			continuationCount = 3;
		} else {
			throw std::runtime_error("Password must be valid UTF-8");
		}
		if (index + continuationCount >= password.size()) {
			throw std::runtime_error("Password must be valid UTF-8");
		}
		for (std::size_t offset = 1; offset <= continuationCount; ++offset) {
			if ((static_cast<unsigned char>(password[index + offset]) & 0xc0) !=
				0x80) {
				throw std::runtime_error("Password must be valid UTF-8");
			}
		}
		if (continuationCount > 0) {
			const unsigned char second =
				static_cast<unsigned char>(password[index + 1]);
			if ((lead == 0xe0 && second < 0xa0) ||
				(lead == 0xed && second >= 0xa0) ||
				(lead == 0xf0 && second < 0x90) ||
				(lead == 0xf4 && second > 0x8f)) {
				throw std::runtime_error("Password must be valid UTF-8");
			}
		}
		index += continuationCount + 1;
	}
	return count;
}
} // namespace

namespace Auth::Detail {

std::string normalizeUsername(std::string_view username) {
	if (username.size() < AppConfigLimits::MIN_USERNAME_LENGTH ||
		username.size() > AppConfigLimits::MAX_USERNAME_LENGTH) {
		return {};
	}
	std::string normalized;
	normalized.reserve(username.size());
	for (const unsigned char character : username) {
		const bool isAsciiLetter = (character >= 'A' && character <= 'Z') ||
								   (character >= 'a' && character <= 'z');
		const bool isAsciiDigit = character >= '0' && character <= '9';
		if (!(isAsciiLetter || isAsciiDigit || character == '.' ||
			  character == '_' || character == '-')) {
			return {};
		}
		normalized.push_back(static_cast<char>(
			character >= 'A' && character <= 'Z' ? character + ('a' - 'A')
												 : character));
	}
	return normalized;
}

void validatePassword(std::string_view password, const PasswordPolicy &policy) {
	if (password.size() > AppConfigLimits::MAX_PASSWORD_BYTES) {
		throw std::runtime_error("Password exceeds the maximum encoded size");
	}
	const std::size_t length = passwordCodepoints(password);
	if (length < policy.minimumCharacters ||
		length > policy.maximumCharacters) {
		throw std::runtime_error(
			"Password does not meet the configured length policy");
	}
}

std::string hashPassword(std::string_view		   password,
						 const Argon2idParameters &parameters) {
	const auto			  salt = secureRandomBytes<ARGON2_SALT_BYTES>();
	std::array<char, 256> encoded{};
	const int			  result = argon2id_hash_encoded(
		parameters.iterations, parameters.memoryKiB, parameters.parallelism,
		password.data(), password.size(), salt.data(), salt.size(),
		ARGON2_HASH_BYTES, encoded.data(), encoded.size());
	if (result != ARGON2_OK) {
		throw std::runtime_error(
			std::string("Argon2id password hashing failed: ") +
			argon2_error_message(result));
	}
	return encoded.data();
}

bool verifyPassword(std::string_view encoded, std::string_view password) {
	const std::string hash(encoded);
	const int		  result =
		argon2id_verify(hash.c_str(), password.data(), password.size());
	if (result == ARGON2_OK) {
		return true;
	}
	if (result == ARGON2_VERIFY_MISMATCH) {
		return false;
	}
	throw std::runtime_error(
		std::string("Argon2id password verification failed: ") +
		argon2_error_message(result));
}

std::string createSessionToken() {
	const auto bytes = secureRandomBytes<AppConfigLimits::TOKEN_BYTES>();
	return hexEncode(bytes.data(), bytes.size());
}

std::string hashSessionToken(std::string_view token) {
	std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
	unsigned int							   digestLength = 0;
	if (EVP_Digest(token.data(), token.size(), digest.data(), &digestLength,
				   EVP_sha256(), nullptr) != 1) {
		throw std::runtime_error("Unable to hash API session token");
	}
	return hexEncode(digest.data(), digestLength);
}

std::string makeUuid() {
	auto bytes = secureRandomBytes<16>();
	bytes[6]   = static_cast<unsigned char>((bytes[6] & 0x0f) | 0x40);
	bytes[8]   = static_cast<unsigned char>((bytes[8] & 0x3f) | 0x80);
	const std::string value = hexEncode(bytes.data(), bytes.size());
	return value.substr(0, 8) + "-" + value.substr(8, 4) + "-" +
		   value.substr(12, 4) + "-" + value.substr(16, 4) + "-" +
		   value.substr(20);
}

} // namespace Auth::Detail
