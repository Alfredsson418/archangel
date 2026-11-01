#include "http/tls.hpp"

#include <openssl/err.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace Http {

namespace {

/**
 * @brief Opens a file without following symlinks and returns its metadata.
 * @param path File to inspect.
 * @param description Name used in error messages.
 * @return The file's metadata.
 * @throws std::runtime_error If the file cannot be opened or is not regular.
 */
struct stat inspectFile(const std::string &path, const char *description) {
	const int descriptor =
		open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor == -1) {
		throw std::runtime_error(std::string("Unable to open TLS ") +
								 description + ": " + std::strerror(errno));
	}
	struct stat info {};
	const bool	ok = fstat(descriptor, &info) == 0 && S_ISREG(info.st_mode);
	close(descriptor);
	if (!ok) {
		throw std::runtime_error(std::string("TLS ") + description +
								 " must be a regular file");
	}
	return info;
}

/**
 * @brief Describes the most recent OpenSSL error.
 * @param fallback Text used when OpenSSL queued no error.
 * @return The OpenSSL error string, or fallback.
 */
std::string openSslError(const char *fallback) {
	const unsigned long code = ERR_get_error();
	ERR_clear_error();
	if (code == 0) {
		return fallback;
	}
	char buffer[256];
	ERR_error_string_n(code, buffer, sizeof(buffer));
	return buffer;
}

} // namespace

void validateTlsFiles(const Config::AppConfig::Tls &tls) {
	const struct stat certificate =
		inspectFile(tls.certificate_file, "certificate file");
	if ((certificate.st_mode & 0022) != 0) {
		throw std::runtime_error(
			"TLS certificate file must not be writable by group or others");
	}
	const struct stat key =
		inspectFile(tls.private_key_file, "private key file");
	if (key.st_uid != geteuid() || (key.st_mode & 0077) != 0) {
		throw std::runtime_error(
			"TLS private key file must be owned by the service user with no "
			"group or other permissions");
	}
}

bool configureTlsContext(SSL_CTX *context, const Config::AppConfig::Tls &tls,
						 std::string &error) {
	ERR_clear_error();
	if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
		error = "Unable to require TLS 1.2 or newer: " +
				openSslError("unknown error");
		return false;
	}
	if (SSL_CTX_use_certificate_chain_file(context,
										   tls.certificate_file.c_str()) != 1) {
		error = "Unable to load the TLS certificate: " +
				openSslError("unknown error");
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(context, tls.private_key_file.c_str(),
									SSL_FILETYPE_PEM) != 1) {
		error = "Unable to load the TLS private key: " +
				openSslError("unknown error");
		return false;
	}
	if (SSL_CTX_check_private_key(context) != 1) {
		error = "TLS private key does not match the certificate: " +
				openSslError("mismatch");
		return false;
	}
	return true;
}

} // namespace Http
