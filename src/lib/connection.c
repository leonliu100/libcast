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

#define CAST_CTRL_PORT 8009

struct cast_connection {
	struct cast_ssl_connection *ssl_conn;
};

struct cast_message {
	CastMessage *protobuf_msg;
};

static int send_handshake(struct cast_connection *conn)
{
	CastMessage msg = CAST_MESSAGE__INIT;
	ssize_t sent, len;
	uint32_t nlen;
	void *buf;

	msg.protocol_version = CAST_MESSAGE__PROTOCOL_VERSION__CASTV2_1_0;
	msg.source_id = "sender-0";
	msg.destination_id = "receiver-0";
	msg.namespace_ = "urn:x-cast:com.google.cast.tp.connection";
	msg.payload_type = CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg.payload_utf8 = "{ \"type\": \"CONNECT\" }";

	len = cast_message__get_packed_size(&msg);
	buf = malloc(len);
	if (!buf)
		return -CAST_ENOMEM;

	cast_message__pack(&msg, buf);
	nlen = htonl(len);

	sent = cast_ssl_full_write(conn->ssl_conn, &nlen, sizeof(uint32_t));
	if (sent != sizeof(uint32_t)) {
		free(buf);
		return -CAST_ESHORTWRITE;
	}

	sent = cast_ssl_full_write(conn->ssl_conn, buf, len);
	if (sent != len) {
		free(buf);
		return -CAST_ESHORTWRITE;
	}

	free(buf);

	return CAST_OK;
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

	msg->protobuf_msg = cast_message__unpack(NULL, len, buf);
	if (!msg)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	return msg;
}

int cast_send_ping(struct cast_connection *conn)
{
	CastMessage msg = CAST_MESSAGE__INIT;
	ssize_t sent, len;
	uint32_t nlen;
	void *buf;

	msg.protocol_version = CAST_MESSAGE__PROTOCOL_VERSION__CASTV2_1_0;
	msg.source_id = "sender-0";
	msg.destination_id = "receiver-0";
	msg.namespace_ = "urn:x-cast:com.google.cast.tp.heartbeat";
	msg.payload_type = CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg.payload_utf8 = "{ \"type\": \"PING\" }";

	len = cast_message__get_packed_size(&msg);
	buf = malloc(len);
	if (!buf)
		return -CAST_ENOMEM;

	cast_message__pack(&msg, buf);
	nlen = htonl(len);

	sent = cast_ssl_full_write(conn->ssl_conn, &nlen, sizeof(uint32_t));
	if (sent != sizeof(uint32_t)) {
		free(buf);
		return -CAST_ESHORTWRITE;
	}

	sent = cast_ssl_full_write(conn->ssl_conn, buf, len);
	if (sent != len) {
		free(buf);
		return -CAST_ESHORTWRITE;
	}

	free(buf);

	return CAST_OK;
}

void cast_msg_free(struct cast_message *msg)
{
	if (msg->protobuf_msg)
		cast_message__free_unpacked(msg->protobuf_msg, NULL);

	free(msg);
}
