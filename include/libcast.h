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

#define CAST_UNUSED		__attribute__((unused))
#define CAST_API		__attribute__((visibility("default")))
#define CAST_NORETURN		__attribute__((noreturn))

#define CAST_ARRAY_SIZE(x)	(sizeof(x) / sizeof(*(x)))

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
	CAST_ECONNCLOSED,
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

typedef void (*cast_log_callback)(int, const char *, void *);

CAST_API void cast_log_level_set(int level);

CAST_API void cast_log_callback_set(cast_log_callback cb, void *priv);

struct cast_list_head {
	struct cast_list_head *next;
	struct cast_list_head *prev;
};
#define CAST_LIST_HEAD_INITIALIZER(list) { &(list), &(list) }

static inline void cast_list_head_init(struct cast_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __cast_list_add(struct cast_list_head *new,
				   struct cast_list_head *prev,
				   struct cast_list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void cast_list_add(struct cast_list_head *new,
				 struct cast_list_head *head)
{
	__cast_list_add(new, head, head->next);
}

static inline void cast_list_add_tail(struct cast_list_head *new,
				      struct cast_list_head *head)
{
	__cast_list_add(new, head->prev, head);
}

static inline void __cast_list_del(struct cast_list_head * prev,
				   struct cast_list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void cast_list_del(struct cast_list_head *entry)
{
	__cast_list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline int cast_list_empty(const struct cast_list_head *head)
{
	return head == head->next;
}

#define cast_list_entry(ptr, type, member) \
	((void*)(((uint8_t*)(ptr)) - offsetof(type, member)))

#define cast_list_foreach(head, iter) \
	for ((iter) = (head)->next; (iter) != (head); (iter) = (iter)->next)

#define cast_list_foreach_rev(head, iter) \
	for ((iter) = (head)->prev; (iter) != (head); (iter) = (iter)->prev)

#define cast_list_foreach_safe(head, iter, tmp)				\
	for ((iter) = (head)->next, (tmp) = (iter)->next;		\
	    (iter) != (head); (iter) = (tmp), (tmp) = (iter)->next)


enum {
	CAST_DISCOVER_CONTINUE = 0,
	CAST_DISCOVER_STOP,
};

typedef int (*cast_discover_callback)(const char *, const char *, void *);

CAST_API int cast_discover(cast_discover_callback cb,
			   void *priv, unsigned long timeout);

CAST_API int cast_resolve(const char *hostname, uint32_t *ip_addr);

typedef struct cast_payload cast_payload;

enum {
	CAST_PAYLOAD_UNKNOWN,
	CAST_PAYLOAD_CLOSE,
	CAST_PAYLOAD_PING,
	CAST_PAYLOAD_PONG,
};

CAST_API struct cast_payload * cast_payload_ping_new(void);

CAST_API struct cast_payload * cast_payload_pong_new(void);

CAST_API void cast_payload_free(struct cast_payload *payload);

CAST_API int cast_payload_type_get(struct cast_payload *payload);

typedef struct cast_message cast_message;

enum {
	CAST_MSG_NS_UNKNOWN = 0,
	CAST_MSG_NS_CONNECTION,
	CAST_MSG_NS_HEARTBEAT,
	CAST_MSG_NS_RECEIVER,
};

enum {
	CAST_MSG_ID_UNKNOWN = 0,
	CAST_MSG_DST_BROADCAST,
	CAST_MSG_ID_DEFAULT_SENDER,
	CAST_MSG_ID_DEFAULT_RECEIVER,
	CAST_MSG_ID_TRANSPORT,
};

CAST_API struct cast_message * cast_msg_new(int src, int dst, int namespace);

CAST_API void cast_msg_free(struct cast_message *msg);

CAST_API int cast_msg_namespace_get(struct cast_message *msg);

CAST_API int cast_msg_src_get(struct cast_message *msg);

CAST_API int cast_msg_dst_get(struct cast_message *msg);

CAST_API struct cast_payload * cast_msg_payload_get(struct cast_message *msg);

CAST_API void cast_msg_payload_set(struct cast_message *msg,
				   struct cast_payload *payload);

typedef struct cast_connection cast_connection;

CAST_API struct cast_connection * cast_conn_connect(const char *hostname);

CAST_API void cast_conn_close(struct cast_connection *conn);

CAST_API int cast_conn_fd_get(struct cast_connection *conn);

CAST_API int cast_conn_msg_send(struct cast_connection *conn,
				struct cast_message *msg);

CAST_API struct cast_message *
cast_conn_msg_recv(struct cast_connection *conn);

CAST_API int cast_msg_ping_send(struct cast_connection *conn);

CAST_API int cast_msg_pong_respond(struct cast_connection *conn,
				   struct cast_message *ping);

CAST_API int cast_msg_get_status_send(struct cast_connection *conn,
				      int request_id);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCAST_H_ */
