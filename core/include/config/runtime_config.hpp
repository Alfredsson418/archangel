#pragma once

#include "app_config.hpp"

#include <string>

/**
 * @brief Parses a strict version 1 backend runtime configuration.
 * @param content Complete runtime configuration JSON text.
 * @return The central application settings with defaults for omitted fields.
 * @throws std::runtime_error If JSON, keys, types, versions, or values are
 * invalid.
 */
AppConfig parseRuntimeConfig(const std::string &content);

/**
 * @brief Loads and validates a private runtime configuration file.
 * @param path File path to read without following a final-component symlink.
 * @param allowMissing Whether a missing file should return built-in defaults.
 * @return Central application settings, or built-in defaults only when an
 * allowed file is absent.
 * @throws std::runtime_error If the file is unsafe, unreadable, missing when
 * required, or invalid.
 */
AppConfig loadRuntimeConfig(const std::string &path, bool allowMissing);
