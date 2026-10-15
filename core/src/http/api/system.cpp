#include "../../../include/http/api/system.hpp"
#include "../../../include/logger.hpp"
#include "api_common.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>
#include <sys/statvfs.h>
#include <unistd.h>

namespace {
using HttpApi::Detail::Json;

Json percentage(std::uint64_t used, std::uint64_t total) {
	if (total == 0)
		return nullptr;
	return 100.0 * static_cast<double>(used) / static_cast<double>(total);
}

Json collectSystemStatistics() {
	Json stats = Json::object();

	char hostname[256] = {};
	if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
		stats["hostname"] = hostname;
	} else {
		stats["hostname"] = "unknown";
	}

	const long configuredCores = sysconf(_SC_NPROCESSORS_ONLN);
	stats["cpu_cores"]		   = configuredCores > 0 ? configuredCores : 0;
	stats["load_average"]	   = Json::array();
	std::ifstream loadAverageFile("/proc/loadavg");
	double		  loadAverage	= 0;
	bool		  loadAvailable = static_cast<bool>(loadAverageFile);
	for (int index = 0; index < 3; ++index) {
		if (!loadAvailable || !(loadAverageFile >> loadAverage)) {
			loadAvailable = false;
			stats["load_average"].push_back(nullptr);
		} else {
			stats["load_average"].push_back(loadAverage);
		}
	}

	std::uint64_t memoryTotalKb		= 0;
	std::uint64_t memoryAvailableKb = 0;
	std::ifstream memoryInfo("/proc/meminfo");
	std::string	  key;
	std::uint64_t value = 0;
	std::string	  unit;
	while (memoryInfo >> key >> value >> unit) {
		if (key == "MemTotal:")
			memoryTotalKb = value;
		if (key == "MemAvailable:")
			memoryAvailableKb = value;
	}
	const std::uint64_t memoryTotal = memoryTotalKb * 1024;
	const std::uint64_t memoryAvailable =
		std::min(memoryAvailableKb, memoryTotalKb) * 1024;
	const std::uint64_t memoryUsed	= memoryTotal - memoryAvailable;
	stats["memory_total_bytes"]		= memoryTotal;
	stats["memory_available_bytes"] = memoryAvailable;
	stats["memory_used_bytes"]		= memoryUsed;
	stats["memory_usage_percent"]	= percentage(memoryUsed, memoryTotal);

	struct statvfs diskInfo{};
	if (statvfs("/", &diskInfo) == 0) {
		const std::uint64_t blockSize =
			diskInfo.f_frsize ? diskInfo.f_frsize : diskInfo.f_bsize;
		const std::uint64_t diskTotal =
			static_cast<std::uint64_t>(diskInfo.f_blocks) * blockSize;
		const std::uint64_t diskAvailable =
			std::min<std::uint64_t>(diskInfo.f_bavail, diskInfo.f_blocks) *
			blockSize;
		const std::uint64_t diskUsed  = diskTotal - diskAvailable;
		stats["disk_total_bytes"]	  = diskTotal;
		stats["disk_available_bytes"] = diskAvailable;
		stats["disk_used_bytes"]	  = diskUsed;
		stats["disk_usage_percent"]	  = percentage(diskUsed, diskTotal);
	} else {
		stats["disk_total_bytes"]	  = nullptr;
		stats["disk_available_bytes"] = nullptr;
		stats["disk_used_bytes"]	  = nullptr;
		stats["disk_usage_percent"]	  = nullptr;
	}

	std::ifstream uptimeFile("/proc/uptime");
	double		  uptime = 0;
	if (uptimeFile >> uptime) {
		stats["uptime_seconds"] = static_cast<std::uint64_t>(uptime);
	} else {
		stats["uptime_seconds"] = nullptr;
	}
	return stats;
}
} // namespace

namespace HttpApi {

void getSystemStatistics(const httplib::Request &,
						 httplib::Response &response) {
	Logger::API::log("GET /api/v1/system");
	try {
		response.set_content(collectSystemStatistics().dump(),
							 "application/json");
	} catch (const std::exception &error) {
		Detail::sendOperationError(response, "GET /api/v1/system", error,
								   "system_error",
								   "System statistics unavailable");
	}
}

} // namespace HttpApi
