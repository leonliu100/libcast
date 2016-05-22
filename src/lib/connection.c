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
	}
};

static const struct msg_data sources[] = {
	{
		.val = CAST_MSG_SRC_DEFAULT,
		.repr = "sender-0",
	},
	{
		.val = CAST_MSG_SRC_TRANSPORT,
		.repr = "Tr@n$p0rt-0",
	}
};

static const struct msg_data destinations[] = {
	{
		.val = CAST_MSG_DST_DEFAULT,
		.repr = "receiver-0",
	},
	{
		.val = CAST_MSG_DST_TRANSPORT,
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
		goto nomem;

	msg->pbmsg = malloc(sizeof(CastMessage));
	if (!msg->pbmsg)
		goto nomem_msg;

	cast_message__init(msg->pbmsg);
	msg->pbmsg->protocol_version = CAST_PROTOCOL_DEFAULT;

	msg->pbmsg->source_id = msg_data_find_repr(src, sources,
						   CAST_ARRAY_SIZE(sources));
	msg->pbmsg->destination_id = msg_data_find_repr(dst, destinations,
						CAST_ARRAY_SIZE(destinations));
	msg->pbmsg->namespace_ = msg_data_find_repr(namespace, namespaces,
						CAST_ARRAY_SIZE(namespaces));

	if (!msg->pbmsg->source_id ||
	    !msg->pbmsg->destination_id ||
	    !msg->pbmsg->namespace_)
		return CAST_ERR_PTR(-CAST_EINVAL);

	return msg;

nomem_msg:
	free(msg);

nomem:
	return CAST_ERR_PTR(-CAST_ENOMEM);
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
				    sources, CAST_ARRAY_SIZE(sources));

	return src < 0 ? CAST_MSG_SRC_UNKNOWN : src;
}

int cast_msg_dst_get(struct cast_message *msg)
{
	int dst = msg_data_find_val(msg->pbmsg->destination_id,
				    destinations,
				    CAST_ARRAY_SIZE(destinations));

	return dst < 0 ? CAST_MSG_DST_UNKNOWN : dst;
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

	free(msg->pbmsg);
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

struct cast_message * cast_msg_receive(struct cast_connection *conn)
{
	struct cast_message *msg;
	uint8_t buf[1024];
	ssize_t recvd;
	uint32_t len;

	memset(buf, 0, sizeof(buf));
	recvd = cast_ssl_full_read(conn->ssl_conn, &len, sizeof(uint32_t));
	if (recvd != sizeof(uint32_t))
		return CAST_ERR_PTR(-CAST_ESHORTREAD);

	len = ntohl(len);
	recvd = cast_ssl_full_read(conn->ssl_conn, buf, len);
	if (recvd != len)
		return CAST_ERR_PTR(-CAST_ESHORTREAD);

	msg = malloc(sizeof(struct cast_message));
	if (!msg)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	msg->pbmsg = cast_message__unpack(NULL, len, buf);
	if (!msg)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	dump_message("message received:", msg);

	msg->payload = cast_payload_from_string(msg->pbmsg->payload_utf8);
	if (CAST_IS_ERR(msg->payload))
		return (struct cast_message *)msg->payload;

	return msg;
}

int cast_msg_send(struct cast_connection *conn, struct cast_message *msg)
{
	ssize_t sent, len;
	uint32_t nlen;
	void *buf;

	msg->pbmsg->payload_type = CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg->pbmsg->payload_utf8 = cast_payload_to_string(msg->payload);

	len = cast_message__get_packed_size(msg->pbmsg);
	buf = malloc(len);
	if (!buf)
		return -CAST_ENOMEM;

	cast_message__pack(msg->pbmsg, buf);
	nlen = htonl(len);

	sent = cast_ssl_full_write(conn->ssl_conn, &nlen, sizeof(uint32_t));
	if (sent != sizeof(uint32_t)) {
		free(buf);
		return -CAST_ESHORTWRITE;
	}

	sent = cast_ssl_full_write(conn->ssl_conn, buf, len);
	free(buf);
	if (sent != len)
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

	msg = cast_msg_new(CAST_MSG_SRC_DEFAULT,
			   CAST_MSG_DST_DEFAULT, CAST_MSG_NS_CONNECTION);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_connect_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
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
	cast_ssl_close_connection(conn->ssl_conn);
	free(conn);
}

int cast_conn_fd_get(struct cast_connection *conn)
{
	return cast_ssl_connection_get_fd(conn->ssl_conn);
}

int cast_conn_ping(struct cast_connection *conn)
{
	struct cast_message *msg;
	int status;

	msg = cast_msg_new(CAST_MSG_SRC_DEFAULT,
			   CAST_MSG_DST_DEFAULT, CAST_MSG_NS_HEARTBEAT);
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	msg->payload = cast_payload_ping_new();
	if (CAST_IS_ERR(msg->payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(msg->payload);
	}

	status = cast_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}
