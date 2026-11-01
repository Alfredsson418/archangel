#pragma once

/**
 * @brief Parses command-line arguments and runs the selected backend command.
 * @param argc Number of command-line arguments.
 * @param argv Argument vector supplied by the process entry point.
 * @return Process exit status.
 */
int runApplication(int argc, char *argv[]);
