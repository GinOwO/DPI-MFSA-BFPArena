/**
 * @file zdpi_log.c
 * @brief Structured logging implementation.
 *
 * @author Kiran P Das
 * @date 2026-02-22
 * @version 0.1.0
 * @copyright Copyright (c) 2026 ZDPI Project. Licensed under GPL v3.
 */

#include "zdpi_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

static enum zdpi_log_level g_min_level = ZDPI_LOG_INFO;
static int g_use_color = 1;

/* ANSI color codes */
#define CLR_RESET  "\033[0m"
#define CLR_DEBUG  "\033[36m"	/* cyan */
#define CLR_INFO   "\033[32m"	/* green */
#define CLR_WARN   "\033[33m"	/* yellow */
#define CLR_ERROR  "\033[31m"	/* red */
#define CLR_TIME   "\033[90m"	/* dark gray */

static const char *level_str[] = {
	"DEBUG", "INFO ", "WARN ", "ERROR"
};

static const char *level_clr[] = {
	CLR_DEBUG, CLR_INFO, CLR_WARN, CLR_ERROR
};

void zdpi_log_init(enum zdpi_log_level min_level, int use_color)
{
	g_min_level = min_level;
	g_use_color = use_color && isatty(STDERR_FILENO);
}

void zdpi_log(enum zdpi_log_level level, const char *fmt, ...)
{
	if (level < g_min_level)
		return;

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);

	if (g_use_color) {
		fprintf(stderr,
			CLR_TIME "%02d:%02d:%02d.%03ld" CLR_RESET
			" %s%s" CLR_RESET " ",
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			ts.tv_nsec / 1000000,
			level_clr[level], level_str[level]);
	} else {
		fprintf(stderr, "%02d:%02d:%02d.%03ld %s ",
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			ts.tv_nsec / 1000000,
			level_str[level]);
	}

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
}
