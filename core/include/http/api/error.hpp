#pragma once

#include <stdexcept>
#include <string>
#include <utility>

class ApiError : public std::runtime_error {
  public:
	/**
	 * @brief Creates an API exception with its HTTP status and stable error
	 * code.
	 * @param status HTTP status to return to the caller.
	 * @param code Machine-readable error identifier.
	 * @param message Human-readable diagnostic message.
	 */
	ApiError(int status, std::string code, std::string message)
		: std::runtime_error(std::move(message)), status_(status),
		  code_(std::move(code)) {}

	/** @brief Gets the HTTP status associated with this error.
	 * @return The HTTP status code.
	 */
	int status() const noexcept { return status_; }

	/** @brief Gets the stable machine-readable error identifier.
	 * @return A reference to the error code string.
	 */
	const std::string &code() const noexcept { return code_; }

  private:
	int			status_;
	std::string code_;
};

class ValidationError : public ApiError {
  public:
	/**
	 * @brief Creates a client-input validation error.
	 * @param message Description of the invalid request value.
	 */
	explicit ValidationError(std::string message)
		: ApiError(400, "invalid_request", std::move(message)) {}
};
