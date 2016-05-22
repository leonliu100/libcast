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

#ifndef _LIBCAST_H_
#define _LIBCAST_H_

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAST_UNUSED	__attribute__((unused))
#define CAST_API	__attribute__((visibility("default")))
#define CAST_NORETURN	__attribute__((noreturn))

enum {
	CAST_OK = 0,
	CAST_ENOMEM,
	CAST_EINVAL,
	CAST_EDISCOVERY,
	CAST_ERESOLVER,
	CAST_ECONN,
	CAST_ESSL,
	CAST_ESHORTWRITE,
	CAST_ESHORTREAD,
	_CAST_MAX_ERR,
};

/**
 * @brief Convert the libcast error number to a human-readable error string.
 * @param errnum Error number.
 * @return Pointer to a static string containing the error description.
 */
CAST_API const char * cast_strerror(int errnum);

/**
 * @brief Return the current libcast version as a human-readable string.
 * @return Pointer to a static string containing the library version.
 */
CAST_API const char * cast_version_str(void);

static inline intptr_t CAST_PTR_ERR(const void *ptr)
{
	return (intptr_t)ptr;
}

static inline int CAST_IS_ERR(const void *ptr)
{
	return (uintptr_t)ptr >= ((unsigned int) - _CAST_MAX_ERR);
}

enum {
	CAST_LOG_NONE = 0,
	CAST_LOG_ERR,
	CAST_LOG_WARN,
	CAST_LOG_INFO,
	CAST_LOG_DBG,
	CAST_LOG_DUMP,
};

typedef void (*cast_log_callback)(int, const char *);

CAST_API void cast_log_level_set(int level);

CAST_API void cast_log_callback_set(cast_log_callback cb);

enum {
	CAST_DISCOVER_CONTINUE = 0,
	CAST_DISCOVER_STOP,
};

typedef int (*cast_discover_callback)(const char *, const char *, void *);

CAST_API int cast_discover(cast_discover_callback cb,
			   void *priv, unsigned long timeout);

CAST_API int cast_resolve(const char *hostname, uint32_t *ip_addr);

typedef struct cast_connection cast_connection;

CAST_API struct cast_connection * cast_conn_connect(const char *hostname);

CAST_API void cast_conn_close(struct cast_connection *conn);

CAST_API int cast_conn_fd_get(struct cast_connection *conn);

typedef struct cast_message cast_message;

enum {
	CAST_MSG_NS_UNKNOWN = 0,
	CAST_MSG_NS_CONNECTION,
	CAST_MSG_NS_HEARTBEAT,
};

enum {
	CAST_MSG_SRC_UNKNOWN = 0,
	CAST_MSG_SRC_DEFAULT,
	CAST_MSG_SRC_TRANSPORT,
};

enum {
	CAST_MSG_DST_UNKNOWN = 0,
	CAST_MSG_DST_DEFAULT,
	CAST_MSG_DST_TRANSPORT,
};

CAST_API struct cast_message * cast_msg_new(int src, int dst, int namespace);

CAST_API void cast_msg_free(struct cast_message *msg);

CAST_API int cast_msg_namespace_get(struct cast_message *msg);

CAST_API int cast_msg_src_get(struct cast_message *msg);

CAST_API int cast_msg_dst_get(struct cast_message *msg);

CAST_API int cast_msg_send(struct cast_connection *conn,
			   struct cast_message *msg);

CAST_API struct cast_message * cast_msg_receive(struct cast_connection *conn);

typedef struct cast_payload cast_payload;

enum {
	CAST_PAYLOAD_UNKNOWN,
	CAST_PAYLOAD_CLOSE,
	CAST_PAYLOAD_PING,
	CAST_PAYLOAD_PONG,
};

CAST_API struct cast_payload * cast_msg_payload_get(struct cast_message *msg);

CAST_API void cast_msg_payload_set(struct cast_message *msg,
				   struct cast_payload *payload);

CAST_API struct cast_payload * cast_payload_close_new(void);

CAST_API struct cast_payload * cast_payload_ping_new(void);

CAST_API struct cast_payload * cast_payload_pong_new(void);

CAST_API void cast_payload_free(struct cast_payload *payload);

CAST_API int cast_payload_type_get(struct cast_payload *payload);

CAST_API int cast_conn_ping(struct cast_connection *conn);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCAST_H_ */
