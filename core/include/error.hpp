#pragma once

#include <stdexcept>
#include <string>
#include <utility>

class ApiError : public std::runtime_error {
  public:
	ApiError(int status, std::string code, std::string message)
		: std::runtime_error(std::move(message)), status_(status),
		  code_(std::move(code)) {}

	int				   status() const noexcept { return status_; }
	const std::string &code() const noexcept { return code_; }

  private:
	int			status_;
	std::string code_;
};

class ValidationError : public ApiError {
  public:
	explicit ValidationError(std::string message)
		: ApiError(400, "invalid_request", std::move(message)) {}
};
