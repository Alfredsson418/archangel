#include "http/tls.hpp"
#include "test_support.hpp"

#include <openssl/ssl.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>

namespace {
namespace fs = std::filesystem;

// Self-signed, test-only certificate for localhost and the matching key, plus
// an unrelated key. Never use these outside tests.
constexpr char TEST_CERTIFICATE[]  = R"(-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUPrPP1NPFEUw5Lt1GFucjsgYR7mIwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTEwMTE5MDYwN1oYDzIxMjYxMDA4
MTkwNjA3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASb2q8zWUJuKfJIHthGTJ1dPnkxA3gTDwylAl/1MtJ+NjONI/NReNUA
JFayCV5S7VBqj9qoxn3L7cwxGMON751Po28wbTAdBgNVHQ4EFgQUjjh7YyL/2Dj0
GXMrG043t/Z290IwHwYDVR0jBBgwFoAUjjh7YyL/2Dj0GXMrG043t/Z290IwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIgULF3skpv5OQvhgptzX/DuNWnPriPbRmmu464D6/LxVwCIQDh
opWWbd3Qpy7TeAvfn+osqZQgpnjFVzskkUIRakiBXg==
-----END CERTIFICATE-----
)";
constexpr char TEST_PRIVATE_KEY[]  = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVD4EdvnqzY0AcZL8
jBxwQXaoCgCZd+Yf++3hQozpzy+hRANCAASb2q8zWUJuKfJIHthGTJ1dPnkxA3gT
DwylAl/1MtJ+NjONI/NReNUAJFayCV5S7VBqj9qoxn3L7cwxGMON751P
-----END PRIVATE KEY-----
)";
constexpr char OTHER_PRIVATE_KEY[] = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeLOqYq33qt8uK3rN
CdbqKkpAO8OmOnE6hJPFcCk5mROhRANCAASabTyrIu4lhTBe5FBAA4Rb34+T/f6P
64dBGnUl+HIDeV50GoZf+pXzd7sKU9A78HJlKUYCa4I7x4+E1sLqW8Xo
-----END PRIVATE KEY-----
)";

class TemporaryDirectory {
  public:
	TemporaryDirectory() {
		char pattern[] = "/tmp/archangel-tls-test-XXXXXX";
		if (mkdtemp(pattern) == nullptr) {
			throw std::runtime_error("Unable to create a temporary directory");
		}
		path = pattern;
	}
	~TemporaryDirectory() {
		std::error_code error;
		fs::remove_all(path, error);
	}
	fs::path path;
};

fs::path writeFile(const fs::path &path, const char *content, mode_t mode) {
	std::ofstream(path) << content;
	chmod(path.c_str(), mode);
	return path;
}

AppConfig::Tls tlsConfig(const fs::path &certificate, const fs::path &key) {
	AppConfig::Tls tls;
	tls.enabled			 = true;
	tls.certificate_file = certificate.string();
	tls.private_key_file = key.string();
	return tls;
}

bool configure(const AppConfig::Tls &tls, std::string &error) {
	SSL_CTX	  *context = SSL_CTX_new(TLS_server_method());
	const bool ok	   = HttpApi::configureTlsContext(context, tls, error);
	if (ok) {
		TestSupport::require(SSL_CTX_get_min_proto_version(context) ==
								 TLS1_2_VERSION,
							 "the listener must require TLS 1.2 or newer");
	}
	SSL_CTX_free(context);
	return ok;
}

void acceptsAMatchingCertificateAndKey() {
	TemporaryDirectory directory;
	const auto		   tls = tlsConfig(
		writeFile(directory.path / "server.crt", TEST_CERTIFICATE, 0644),
		writeFile(directory.path / "server.key", TEST_PRIVATE_KEY, 0600));
	HttpApi::validateTlsFiles(tls);
	std::string error;
	TestSupport::require(
		configure(tls, error),
		"a matching certificate and key should configure TLS: " + error);
}

void rejectsMismatchedOrMissingFiles() {
	TemporaryDirectory directory;
	const auto		   certificate =
		writeFile(directory.path / "server.crt", TEST_CERTIFICATE, 0644);
	std::string error;
	TestSupport::require(
		!configure(
			tlsConfig(certificate, writeFile(directory.path / "other.key",
											 OTHER_PRIVATE_KEY, 0600)),
			error),
		"a key that does not match the certificate must be rejected (OpenSSL "
		"reports the mismatch while loading the key)");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			HttpApi::validateTlsFiles(
				tlsConfig(certificate, directory.path / "missing.key"));
		},
		"a missing private key must fail validation");
	TestSupport::require(
		!configure(tlsConfig(writeFile(directory.path / "bad.crt",
									   "not a certificate", 0644),
							 directory.path / "other.key"),
				   error),
		"an invalid certificate must be rejected");
}

void rejectsUnsafeKeyPermissions() {
	TemporaryDirectory directory;
	const auto		   certificate =
		writeFile(directory.path / "server.crt", TEST_CERTIFICATE, 0644);
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			HttpApi::validateTlsFiles(
				tlsConfig(certificate, writeFile(directory.path / "shared.key",
												 TEST_PRIVATE_KEY, 0640)));
		},
		"a private key readable by group must be rejected");
	const auto key =
		writeFile(directory.path / "server.key", TEST_PRIVATE_KEY, 0600);
	fs::create_symlink(key, directory.path / "linked.key");
	TestSupport::requireThrows<std::runtime_error>(
		[&] {
			HttpApi::validateTlsFiles(
				tlsConfig(certificate, directory.path / "linked.key"));
		},
		"a symlinked private key must be rejected");
	chmod(certificate.c_str(), 0666);
	TestSupport::requireThrows<std::runtime_error>(
		[&] { HttpApi::validateTlsFiles(tlsConfig(certificate, key)); },
		"a certificate writable by others must be rejected");
}
} // namespace

void runTlsTests() {
	acceptsAMatchingCertificateAndKey();
	rejectsMismatchedOrMissingFiles();
	rejectsUnsafeKeyPermissions();
}
