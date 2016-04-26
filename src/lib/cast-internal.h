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

#ifndef CAST_INTERNAL_H
#define CAST_INTERNAL_H

#include <libcast.h>

#include <sys/time.h>
#include <pthread.h>

#define CAST_INIT_FUNC		__attribute__((constructor))
#define CAST_PRINTF_FUNC(s, f)	__attribute__((format(printf, s, f)))

static inline void * CAST_ERR_PTR(intptr_t error)
{
	return (void *)error;
}

#if ENABLE_DEBUG
CAST_PRINTF_FUNC(1, 2) void cast_dbg(const char *fmt, ...);
#else
static inline void cast_dbg(const char *fmt CAST_UNUSED, ...)
{

}
#endif /* ENABLE_DEBUG */
CAST_PRINTF_FUNC(1, 2) void cast_info(const char *fmt, ...);
CAST_PRINTF_FUNC(1, 2) void cast_warn(const char *fmt, ...);
CAST_PRINTF_FUNC(1, 2) void cast_err(const char *fmt, ...);

struct cast_mutex {
	pthread_mutex_t mutex;
};
#define CAST_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }

void cast_mutex_init(struct cast_mutex *mutex);
void cast_mutex_free(struct cast_mutex *mutex);
void cast_mutex_lock(struct cast_mutex *mutex);
void cast_mutex_unlock(struct cast_mutex *mutex);

struct cast_ssl_connection;

struct cast_ssl_connection * cast_ssl_connect(const char *hostname, int port);
void cast_ssl_close_connection(struct cast_ssl_connection *conn);

int cast_ssl_connection_get_fd(struct cast_ssl_connection *conn);

ssize_t cast_ssl_full_read(struct cast_ssl_connection *conn,
			   void *buf, size_t expected);
ssize_t cast_ssl_full_write(struct cast_ssl_connection *conn,
			    const void *buf, size_t bufsize);

unsigned int cast_timeval_to_msec(struct timeval *tv);

#endif /* CAST_INTERNAL_H */
