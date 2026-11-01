#include "auth/password_blocklist.hpp"
#include "config/app_config.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace Auth {

namespace {
char asciiLower(char character) {
	return character >= 'A' && character <= 'Z'
			   ? static_cast<char>(character - 'A' + 'a')
			   : character;
}
} // namespace

PasswordBlocklist PasswordBlocklist::load(const std::string &path) {
	const int file = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (file == -1) {
		throw std::runtime_error("Unable to open password blocklist: " + path);
	}
	struct stat info {};
	if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) ||
		(info.st_uid != 0 && info.st_uid != geteuid()) ||
		(info.st_mode & 0022) != 0) {
		close(file);
		throw std::runtime_error(
			"Password blocklist must be a regular file owned by root or the "
			"service user and not group/world writable");
	}
	if (info.st_size <= 0 ||
		info.st_size > Config::Limits::MAX_PASSWORD_BLOCKLIST_BYTES) {
		close(file);
		throw std::runtime_error(
			"Password blocklist must be between 1 byte and " +
			std::to_string(Config::Limits::MAX_PASSWORD_BLOCKLIST_BYTES /
						   (1024 * 1024)) +
			" MiB");
	}
	std::string content(static_cast<std::size_t>(info.st_size), '\0');
	std::size_t offset = 0;
	while (offset < content.size()) {
		const ssize_t count =
			read(file, content.data() + offset, content.size() - offset);
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count <= 0) {
			close(file);
			throw std::runtime_error("Unable to read password blocklist: " +
									 path);
		}
		offset += static_cast<std::size_t>(count);
	}
	close(file);
	PasswordBlocklist blocklist = fromContent(std::move(content));
	if (blocklist.size() == 0) {
		throw std::runtime_error("Password blocklist contains no entries: " +
								 path);
	}
	return blocklist;
}

PasswordBlocklist PasswordBlocklist::fromContent(std::string content) {
	std::transform(content.begin(), content.end(), content.begin(), asciiLower);
	PasswordBlocklist blocklist;
	blocklist.content_ =
		std::make_shared<const std::string>(std::move(content));
	const std::string_view text(*blocklist.content_);
	std::size_t			   start = 0;
	while (start < text.size()) {
		std::size_t end = text.find('\n', start);
		if (end == std::string_view::npos) {
			end = text.size();
		}
		std::string_view line = text.substr(start, end - start);
		if (!line.empty() && line.back() == '\r') {
			line.remove_suffix(1);
		}
		if (!line.empty() &&
			line.size() <= Config::Limits::MAX_PASSWORD_BYTES) {
			blocklist.entries_.push_back(line);
		}
		start = end + 1;
	}
	std::sort(blocklist.entries_.begin(), blocklist.entries_.end());
	blocklist.entries_.erase(
		std::unique(blocklist.entries_.begin(), blocklist.entries_.end()),
		blocklist.entries_.end());
	return blocklist;
}

bool PasswordBlocklist::contains(std::string_view password) const {
	if (password.size() > Config::Limits::MAX_PASSWORD_BYTES) {
		return false;
	}
	std::string lowered(password);
	std::transform(lowered.begin(), lowered.end(), lowered.begin(), asciiLower);
	const bool found = std::binary_search(entries_.begin(), entries_.end(),
										  std::string_view(lowered));
	std::fill(lowered.begin(), lowered.end(), '\0');
	return found;
}

std::size_t PasswordBlocklist::size() const { return entries_.size(); }

} // namespace Auth
