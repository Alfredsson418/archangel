#pragma once

#include "config/app_config.hpp"

#include <openssl/ssl.h>

#include <string>

namespace HttpApi {

/**
 * @brief Checks the configured TLS files before the server starts.
 *
 * The certificate must be a regular, non-symlinked file that group and
 * others cannot write. The private key must be a regular, non-symlinked file
 * owned by the service user with no group or other permissions.
 * @param tls Effective TLS settings with enabled set.
 * @return No value.
 * @throws std::runtime_error Naming the first problem found.
 */
void validateTlsFiles(const AppConfig::Tls &tls);

/**
 * @brief Configures an OpenSSL server context for the API listener.
 *
 * Requires TLS 1.2 or newer, loads the certificate chain and private key, and
 * checks that the key matches the certificate.
 * @param context OpenSSL server context to configure.
 * @param tls Effective TLS settings.
 * @param error Receives a description when configuration fails.
 * @return True when the context is ready to serve; false otherwise.
 */
bool configureTlsContext(SSL_CTX *context, const AppConfig::Tls &tls,
						 std::string &error);

} // namespace HttpApi
