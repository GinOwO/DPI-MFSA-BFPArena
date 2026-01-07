/**
 * @file zdpi_log.h
 * @brief Structured logging with ANSI colors and timestamps.
 *
 * Log levels:
 * - ERROR: always shown (red)
 * - INFO:  always shown (green)
 * - WARN:  shown with --warnings or --verbose (yellow)
 * - DEBUG: shown with --verbose only (cyan)
 *
 * @author Kiran P Das
 * @date 2026-02-22
 * @version 0.1.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#ifndef ZDPI_LOG_H
#define ZDPI_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

enum zdpi_log_level {
	ZDPI_LOG_DEBUG = 0,
	ZDPI_LOG_INFO  = 1,
	ZDPI_LOG_WARN  = 2,
	ZDPI_LOG_ERROR = 3,
};

/**
 * @brief Initialize the logging system.
 *
 * @param min_level  Minimum level to display
 * @param use_color  Enable ANSI color output (disable for file/pipe)
 */
void zdpi_log_init(enum zdpi_log_level min_level, int use_color);

/**
 * @brief Log a message at the given level.
 */
void zdpi_log(enum zdpi_log_level level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define LOG_DBG(fmt, ...) \
	zdpi_log(ZDPI_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) \
	zdpi_log(ZDPI_LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) \
	zdpi_log(ZDPI_LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) \
	zdpi_log(ZDPI_LOG_ERROR, fmt, ##__VA_ARGS__)

#endif /* ZDPI_LOG_H */
