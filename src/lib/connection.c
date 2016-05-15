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
};

struct cast_message * cast_msg_new(const char *src,
				   const char *dst, const char *namespace)
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

	msg->pbmsg->source_id = strdup(src);
	if (!msg->pbmsg->source_id)
		goto nomem_pbmsg;

	msg->pbmsg->destination_id = strdup(dst);
	if (!msg->pbmsg->destination_id)
		goto nomem_src;

	msg->pbmsg->namespace_ = strdup(namespace);
	if (!msg->pbmsg->namespace_)
		goto nomem_dst;

	return msg;

nomem_dst:
	free(msg->pbmsg->destination_id);

nomem_src:
	free(msg->pbmsg->source_id);

nomem_pbmsg:
	free(msg->pbmsg);

nomem_msg:
	free(msg);

nomem:
	return CAST_ERR_PTR(-CAST_ENOMEM);
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
	free(msg->pbmsg->namespace_);
	free(msg->pbmsg->destination_id);
	free(msg->pbmsg->source_id);

	if (msg->pbmsg->payload_utf8)
		free(msg->pbmsg->payload_utf8);

	free(msg->pbmsg);
	free(msg);
}

const char * cast_msg_default_sender(void)
{
	return "sender-0";
}

const char * cast_msg_default_receiver(void)
{
	return "receiver-0";
}

const char * cast_msg_namespace_get(int namespace)
{
	switch (namespace) {
	case CAST_MSG_NS_CONNECTION:
		return "urn:x-cast:com.google.cast.tp.connection";
	case CAST_MSG_NS_HEARTBEAT:
		return "urn:x-cast:com.google.cast.tp.heartbeat";
	default:
		return CAST_ERR_PTR(-CAST_EINVAL);
	}
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

	return msg;
}

int cast_msg_send(struct cast_connection *conn, struct cast_message *msg)
{
	ssize_t sent, len;
	uint32_t nlen;
	void *buf;

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

	return CAST_OK;
}

static int send_handshake(struct cast_connection *conn)
{
	struct cast_message *msg;
	char *payload;
	int status;

	msg = cast_msg_new(cast_msg_default_sender(),
			   cast_msg_default_receiver(),
			   cast_msg_namespace_get(CAST_MSG_NS_CONNECTION));
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	payload = cast_json_make_connect_payload();
	if (CAST_IS_ERR(payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(payload);
	}

	status = cast_msg_payload_str_set(msg, payload);
	free(payload);
	if (status != CAST_OK) {
		cast_msg_free(msg);
		return status;
	}

	status = cast_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}

struct cast_connection * cast_connect(const char *hostname)
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
		cast_close_connection(conn);
		return CAST_ERR_PTR(status);
	}

	return conn;
}

void cast_close_connection(struct cast_connection *conn)
{
	cast_ssl_close_connection(conn->ssl_conn);
	free(conn);
}

int cast_connection_get_fd(struct cast_connection *conn)
{
	return cast_ssl_connection_get_fd(conn->ssl_conn);
}

int cast_send_ping(struct cast_connection *conn)
{
	struct cast_message *msg;
	char *payload;
	int status;

	msg = cast_msg_new(cast_msg_default_sender(),
			   cast_msg_default_receiver(),
			   cast_msg_namespace_get(CAST_MSG_NS_HEARTBEAT));
	if (CAST_IS_ERR(msg))
		return CAST_PTR_ERR(msg);

	payload = cast_json_make_ping_payload();
	if (CAST_IS_ERR(payload)) {
		cast_msg_free(msg);
		return CAST_PTR_ERR(payload);
	}

	status = cast_msg_payload_str_set(msg, payload);
	free(payload);
	if (status != CAST_OK) {
		cast_msg_free(msg);
		return status;
	}

	status = cast_msg_send(conn, msg);
	cast_msg_free(msg);

	return status;
}
