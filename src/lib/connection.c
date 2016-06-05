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
#include "message.pb-c.h"

#include <string.h>
#include <arpa/inet.h>

#define CAST_CTRL_PORT		8009
#define CAST_PROTOCOL_DEFAULT	CAST_MESSAGE__PROTOCOL_VERSION__CASTV2_1_0

struct cast_connection {
	struct cast_ssl_connection *ssl_conn;
};

struct cast_message {
	CastMessage *pbmsg;
	int needs_pb_free;
	cast_payload *payload;
};

struct msg_data {
	int val;
	char *repr;
};

static const struct msg_data namespaces[] = {
	{
		.val = CAST_MSG_NS_CONNECTION,
		.repr = "urn:x-cast:com.google.cast.tp.connection",
	},
	{
		.val = CAST_MSG_NS_HEARTBEAT,
		.repr = "urn:x-cast:com.google.cast.tp.heartbeat",
	},
	{
		.val = CAST_MSG_NS_RECEIVER,
		.repr = "urn:x-cast:com.google.cast.receiver",
	}
};

static const struct msg_data ids[] = {
	{
		.val = CAST_MSG_DST_BROADCAST,
		.repr = "*",
	},
	{
		.val = CAST_MSG_ID_DEFAULT_SENDER,
		.repr = "sender-0",
	},
	{
		.val = CAST_MSG_ID_DEFAULT_RECEIVER,
		.repr = "receiver-0",
	},
	{
		.val = CAST_MSG_ID_TRANSPORT,
		.repr = "Tr@n$p0rt-0",
	}
};

static char * msg_data_find_repr(int val, const struct msg_data *data,
				 size_t size)
{
	unsigned int i;

	for (i = 0; i < size; i++) {
		if (data[i].val == val)
			return data[i].repr;
	}

	return NULL;
}

static int msg_data_find_val(const char *repr,
			     const struct msg_data *data, size_t size)
{
	unsigned int i;

	for (i = 0; i < size; i++) {
		if (strcmp(data[i].repr, repr) == 0)
			return data[i].val;
	}

	return -1;
}

struct cast_message * cast_msg_new(int src, int dst, int namespace)
{
	struct cast_message *msg;

	msg = malloc(sizeof(struct cast_message));
	if (!msg)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	msg->pbmsg = malloc(sizeof(CastMessage));
	if (!msg->pbmsg) {
		free(msg);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}
	msg->needs_pb_free = 0;

	cast_message__init(msg->pbmsg);
	msg->pbmsg->protocol_version = CAST_PROTOCOL_DEFAULT;

	msg->pbmsg->source_id = msg_data_find_repr(src, ids,
						   CAST_ARRAY_SIZE(ids));
	msg->pbmsg->destination_id = msg_data_find_repr(dst, ids,
						CAST_ARRAY_SIZE(ids));
	msg->pbmsg->namespace_ = msg_data_find_repr(namespace, namespaces,
						CAST_ARRAY_SIZE(namespaces));

	if (!msg->pbmsg->source_id ||
	    !msg->pbmsg->destination_id ||
	    !msg->pbmsg->namespace_) {
		free(msg->pbmsg);
		free(msg);
		return CAST_ERR_PTR(-CAST_EINVAL);
	}

	return msg;
}

int cast_msg_namespace_get(struct cast_message *msg)
{
	int ns = msg_data_find_val(msg->pbmsg->namespace_,
				   namespaces, CAST_ARRAY_SIZE(namespaces));

	return ns < 0 ? CAST_MSG_NS_UNKNOWN : ns;
}

int cast_msg_src_get(struct cast_message *msg)
{
	int src = msg_data_find_val(msg->pbmsg->source_id,
				    ids, CAST_ARRAY_SIZE(ids));

	return src < 0 ? CAST_MSG_ID_UNKNOWN : src;
}

int cast_msg_dst_get(struct cast_message *msg)
{
	int dst = msg_data_find_val(msg->pbmsg->destination_id,
				    ids, CAST_ARRAY_SIZE(ids));

	return dst < 0 ? CAST_MSG_ID_UNKNOWN : dst;
}

int cast_msg_payload_str_set(struct cast_message *msg, const char *payload)
{
	msg->pbmsg->payload_type = CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg->pbmsg->payload_utf8 = strdup(payload);
	if (!msg->pbmsg->payload_utf8)
		return -CAST_ENOMEM;

	return CAST_OK;
}

void cast_msg_free(struct cast_message *msg)
{
	if (msg->payload)
		cast_payload_free(msg->payload);

	if (msg->pbmsg) {
		if (msg->needs_pb_free)
			cast_message__free_unpacked(msg->pbmsg, NULL);
		else
			free(msg->pbmsg);
	}

	free(msg);
}

static void dump_message(const char *hdr, struct cast_message *msg)
{
	cast_dump("%s", hdr);
	cast_dump("  %-16s%s", "source_id:", msg->pbmsg->source_id);
	cast_dump("  %-16s%s", "destination_id:", msg->pbmsg->destination_id);
	cast_dump("  %-16s%s", "namespace:", msg->pbmsg->namespace_);
	cast_dump("  %-16s%s", "payload:", msg->pbmsg->payload_utf8);
}

struct cast_message * cast_conn_msg_recv(struct cast_connection *conn)
{
	struct cast_message *msg;
	ssize_t recvd;
	uint32_t len;
	uint8_t *buf;

	recvd = cast_ssl_full_read(conn->ssl_conn, &len, sizeof(uint32_t));
	if (recvd == -CAST_ECONNCLOSED)
		return CAST_ERR_PTR(recvd);
	if (recvd != sizeof(len))
		return CAST_ERR_PTR(-CAST_ESHORTREAD);

	len = ntohl(len);

	buf = malloc(len);
	if (!buf)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	recvd = cast_ssl_full_read(conn->ssl_conn, buf, len);
	if (recvd != len) {
		free(buf);
		return CAST_ERR_PTR(-CAST_ESHORTREAD);
	}

	msg = malloc(sizeof(*msg));
	if (!msg) {
		free(buf);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	msg->pbmsg = cast_message__unpack(NULL, len, buf);
	free(buf);
	if (!msg->pbmsg) {
		cast_msg_free(msg);
		return CAST_ERR_PTR(-CAST_EINVAL);
	}
	msg->needs_pb_free = 1;

	dump_message("message received:", msg);

	msg->payload = cast_payload_from_string(msg->pbmsg->payload_utf8);
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return (struct cast_message *)msg->payload;
	}

	return msg;
}

struct msg_buf {
	uint32_t size;
	uint8_t data[0];
} CAST_PACKED;

int cast_conn_msg_send(struct cast_connection *conn, struct cast_message *msg)
{
	struct msg_buf *buf;
	ssize_t sent, len;
	size_t msgsize;

	msg->pbmsg->payload_type = CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg->pbmsg->payload_utf8 = cast_payload_to_string(msg->payload);

	len = cast_message__get_packed_size(msg->pbmsg);
	msgsize = len + sizeof(buf->size);

	buf = malloc(msgsize);
	if (!buf)
		return -CAST_ENOMEM;

	cast_message__pack(msg->pbmsg, buf->data);
	buf->size = htonl(len);

	sent = cast_ssl_full_write(conn->ssl_conn, buf, msgsize);
	free(buf);
	if (sent != (ssize_t)msgsize)
		return -CAST_ESHORTWRITE;

	dump_message("message sent:", msg);

	return CAST_OK;
}

struct cast_payload * cast_msg_payload_get(struct cast_message *msg)
{
	return msg->payload;
}

void cast_msg_payload_set(struct cast_message *msg,
			  struct cast_payload *payload)
{
	msg->payload = payload;
}

static int send_handshake(struct cast_connection *conn)
{
	struct cast_message *msg;
	int status;

	msg = cast_msg_new(CAST_MSG_ID_DEFAULT_SENDER,
			   CAST_MSG_ID_DEFAULT_RECEIVER,
			   CAST_MSG_NS_CONNECTION);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_connect_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_conn_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}

static void send_close(struct cast_connection *conn)
{
	struct cast_message *msg;

	msg = cast_msg_new(CAST_MSG_ID_DEFAULT_SENDER,
			   CAST_MSG_ID_DEFAULT_RECEIVER,
			   CAST_MSG_NS_CONNECTION);
	if (CAST_IS_ERR(msg))
		return;

	msg->payload = cast_payload_close_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return;
	}

	cast_conn_msg_send(conn, msg);
	cast_msg_free(msg);
}

struct cast_connection * cast_conn_connect(const char *hostname)
{
	struct cast_ssl_connection *ssl_conn;
	struct cast_connection *conn;
	int status;

	ssl_conn = cast_ssl_connect(hostname, CAST_CTRL_PORT);
	if (CAST_IS_ERR(ssl_conn))
		return (struct cast_connection *)ssl_conn;

	conn = malloc(sizeof(struct cast_connection));
	if (!conn) {
		cast_ssl_close_connection(ssl_conn);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	conn->ssl_conn = ssl_conn;

	status = send_handshake(conn);
	if (status) {
		cast_conn_close(conn);
		return CAST_ERR_PTR(status);
	}

	return conn;
}

void cast_conn_close(struct cast_connection *conn)
{
	send_close(conn);
	cast_ssl_close_connection(conn->ssl_conn);
	free(conn);
}

int cast_conn_fd_get(struct cast_connection *conn)
{
	return cast_ssl_connection_get_fd(conn->ssl_conn);
}

int cast_msg_ping_send(struct cast_connection *conn)
{
	struct cast_message *msg;
	int status;

	msg = cast_msg_new(CAST_MSG_ID_TRANSPORT,
			   CAST_MSG_ID_TRANSPORT, CAST_MSG_NS_HEARTBEAT);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_ping_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_conn_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}

int cast_msg_pong_respond(struct cast_connection *conn,
			  struct cast_message *ping)
{
	struct cast_message *msg;
	int status, ns, type;

	ns = cast_msg_namespace_get(ping);
	if (ns != CAST_MSG_NS_HEARTBEAT)
		return -CAST_EINVAL;

	type = cast_payload_type_get(cast_msg_payload_get(ping));
	if (type != CAST_PAYLOAD_PING)
		return -CAST_EINVAL;

	msg = cast_msg_new(cast_msg_dst_get(ping),
			   cast_msg_src_get(ping), CAST_MSG_NS_HEARTBEAT);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_pong_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_conn_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}

int cast_msg_get_status_send(struct cast_connection *conn, int request_id)
{
	struct cast_message *msg;
	int status;

	msg = cast_msg_new(CAST_MSG_ID_DEFAULT_SENDER,
			   CAST_MSG_ID_DEFAULT_RECEIVER, CAST_MSG_NS_RECEIVER);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_get_status_new(request_id);
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_conn_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}
