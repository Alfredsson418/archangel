#pragma once

#include <string>

class CLI_ARGS {

  public:
	/* ========================
	 *	General Options
	 * ========================
	 */
	static bool verbose;

	/* ========================
	 *    HTTP Endpoint Options
	 *  ========================
	 */
	static std::string	  http_hostname;
	static unsigned short http_port;
	static std::string	  import_config_path;
	static std::string	  export_config_path;

	CLI_ARGS() = delete; // This would simulate a "static" class
};
