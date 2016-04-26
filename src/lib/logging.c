/*
 * Copyright (C) 2016 Bartosz Golaszewski <bartekgola@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "cast-internal.h"

#include <stdio.h>
#include <stdarg.h>

static const char *const env_name = "CAST_LOG_LEVEL";

static struct cast_mutex log_mutex = CAST_MUTEX_INITIALIZER;
static int log_level;
static int log_env_overridden;
static cast_log_callback log_callback;

CAST_INIT_FUNC static void init_log_level(void)
{
	char *env;

	env = getenv(env_name);
	if (env) {
		log_env_overridden = 1;
		log_level = atoi(env);
	}
}

static const char * level_to_header(int level)
{
	switch (level) {
	case CAST_LOG_ERR:	return "[ERROR]";
	case CAST_LOG_WARN:	return "[WARNING]";
	case CAST_LOG_INFO:	return "[INFO]";
	case CAST_LOG_DBG:	return "[DEBUG]";
	default:		return "[UNKNOWN]";
	}
}

static void emit_msg(int level, const char *fmt, va_list va)
{
	char buf[256];

	vsnprintf(buf, sizeof(buf), fmt, va);

	cast_mutex_lock(&log_mutex);

	if (level <= log_level) {
		fprintf(stderr, "libcast %-10s%s\n",
			level_to_header(level), buf);
	}

	/*
	 * Always emit logs if a callback function is present. Let the user
	 * decide if he wants to suppress certain levels.
	 */
	if (log_callback)
		log_callback(level, buf);

	cast_mutex_unlock(&log_mutex);
}

void cast_log_level_set(int level)
{
	cast_mutex_lock(&log_mutex);
	if (!log_env_overridden)
		log_level = level;
	cast_mutex_unlock(&log_mutex);
}

void cast_log_callback_set(cast_log_callback cb)
{
	cast_mutex_lock(&log_mutex);
	log_callback = cb;
	cast_mutex_unlock(&log_mutex);
}

#if ENABLE_DEBUG
void cast_dbg(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	emit_msg(CAST_LOG_DBG, fmt, va);
	va_end(va);
}
#endif /* ENABLE_DEBUG */

void cast_info(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	emit_msg(CAST_LOG_INFO, fmt, va);
	va_end(va);
}

void cast_warn(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	emit_msg(CAST_LOG_WARN, fmt, va);
	va_end(va);
}

void cast_err(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	emit_msg(CAST_LOG_ERR, fmt, va);
	va_end(va);
}
