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

/* TODO Add some locking for the static variables below? */

static int log_level;
static int log_env_overridden;
static cast_log_callback log_callback;
static void *log_callback_priv;

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
	case CAST_LOG_DUMP:	return "[DUMP]";
	default:		return "[UNKNOWN]";
	}
}

static void emit_msg(int level, const char *fmt, va_list va)
{
	int current_level, written;
	char buf[256];
	char *msg = buf;
	va_list vacpy;

	current_level = log_level;

	va_copy(vacpy, va);
	written = vsnprintf(buf, sizeof(buf), fmt, vacpy);
	va_end(vacpy);
	if (written > (int)sizeof(buf)) {
		msg = malloc(written + 1);
		if (!msg)
			msg = buf;
		else
			vsnprintf(msg, written + 1, fmt, va);
	}

	if (level <= current_level) {
		fprintf(stderr, "libcast %-10s%s\n",
			level_to_header(level), msg);
	}

	/*
	 * Always emit logs if a callback function is present. Let the user
	 * decide if he wants to suppress certain levels.
	 */
	if (log_callback)
		log_callback(level, msg, log_callback_priv);

	if (msg != buf)
		free(msg);
}

void cast_log_level_set(int level)
{
	if (!log_env_overridden)
		log_level = level;
}

void cast_log_callback_set(cast_log_callback cb, void *priv)
{
	log_callback = cb;
	log_callback_priv = priv;
}

#if ENABLE_DEBUG
void cast_dump(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	emit_msg(CAST_LOG_DUMP, fmt, va);
	va_end(va);
}

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
