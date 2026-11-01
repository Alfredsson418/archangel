#include "auth/secret_input.hpp"
#include "config/app_config.hpp"

#include <openssl/crypto.h>

#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <utility>

namespace Auth {

SecretString::SecretString(std::string value) : value_(std::move(value)) {}

SecretString::~SecretString() { OPENSSL_cleanse(value_.data(), value_.size()); }

const std::string &SecretString::value() const { return value_; }

namespace {
class TerminalPasswordPrompt {
  public:
	TerminalPasswordPrompt() {
		file_ = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
		if (file_ == -1) {
			throw std::runtime_error(
				"Password entry requires an interactive terminal");
		}
		if (tcgetattr(file_, &original_) != 0) {
			close(file_);
			file_ = -1;
			throw std::runtime_error("Unable to configure password prompt");
		}
		termios hidden = original_;
		hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
		if (tcsetattr(file_, TCSAFLUSH, &hidden) != 0) {
			close(file_);
			file_ = -1;
			throw std::runtime_error(
				"Unable to disable terminal password echo");
		}
		echoDisabled_ = true;
	}

	~TerminalPasswordPrompt() {
		if (echoDisabled_) {
			tcsetattr(file_, TCSAFLUSH, &original_);
		}
		if (file_ != -1) {
			close(file_);
		}
	}

	std::string read(const char *prompt) {
		std::string password;
		bool		tooLong = false;
		try {
			writeAll(prompt);
			for (;;) {
				char		  character = '\0';
				const ssize_t result	= ::read(file_, &character, 1);
				if (result == -1 && errno == EINTR) {
					continue;
				}
				if (result != 1) {
					throw std::runtime_error(
						"Unable to read password from terminal");
				}
				if (character == '\n' || character == '\r') {
					break;
				}
				if (password.size() < AppConfigLimits::MAX_PASSWORD_BYTES) {
					password.push_back(character);
				} else {
					tooLong = true;
				}
			}
			writeAll("\n");
			if (tooLong) {
				throw std::runtime_error("Password exceeds the maximum length");
			}
		} catch (...) {
			OPENSSL_cleanse(password.data(), password.size());
			throw;
		}
		return password;
	}

  private:
	void writeAll(const char *text) {
		std::size_t remaining = std::char_traits<char>::length(text);
		const char *cursor	  = text;
		while (remaining > 0) {
			const ssize_t written = ::write(file_, cursor, remaining);
			if (written == -1 && errno == EINTR) {
				continue;
			}
			if (written <= 0) {
				throw std::runtime_error("Unable to write password prompt");
			}
			cursor += written;
			remaining -= static_cast<std::size_t>(written);
		}
	}

	int		file_ = -1;
	termios original_{};
	bool	echoDisabled_ = false;
};
} // namespace

std::string promptPassword(const char *prompt) {
	TerminalPasswordPrompt terminal;
	return terminal.read(prompt);
}

} // namespace Auth
