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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

CAST_INIT_FUNC static void init_openssl(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

struct cast_ssl_connection {
	BIO *bio;
	SSL_CTX *ssl_ctx;
};

static void print_all_ssl_errors(void)
{
	unsigned long error;

	while ((error = ERR_get_error()))
		cast_err("ssl error: %s", ERR_reason_error_string(error));
}

struct cast_ssl_connection * cast_ssl_connect(const char *hostname, int port)
{
	struct cast_ssl_connection *conn, *ret;
	char hostbuf[256];
	long status;
	SSL *ssl;

	conn = malloc(sizeof(struct cast_ssl_connection));
	if (!conn) {
		ret = CAST_ERR_PTR(-CAST_ENOMEM);
		goto errout;
	}

	conn->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!conn->ssl_ctx) {
		print_all_ssl_errors();
		ret = CAST_ERR_PTR(-CAST_ESSL);
		goto free_conn;
	}

	conn->bio = BIO_new_ssl_connect(conn->ssl_ctx);
	if (!conn->bio) {
		print_all_ssl_errors();
		ret = CAST_ERR_PTR(-CAST_ESSL);
		goto free_ssl_ctx;
	}

	BIO_get_ssl(conn->bio, &ssl);
	if (!ssl) {
		print_all_ssl_errors();
		ret = CAST_ERR_PTR(-CAST_ESSL);
		goto free_bio;
	}

	snprintf(hostbuf, sizeof(hostbuf), "%s:%d", hostname, port);
	BIO_set_conn_hostname(conn->bio, hostbuf);

	status = BIO_do_connect(conn->bio);
	if (status != 1) {
		print_all_ssl_errors();
		ret = CAST_ERR_PTR(-CAST_ESSL);
		goto free_bio;
	}

	cast_dbg("ssl connection to %s:%d established", hostname, port);

	return conn;

free_bio:
	BIO_free(conn->bio);

free_ssl_ctx:
	SSL_CTX_free(conn->ssl_ctx);

free_conn:
	free(conn);

errout:
	return ret;
}

void cast_ssl_close_connection(struct cast_ssl_connection *conn)
{
	BIO_ssl_shutdown(conn->bio);
	BIO_free_all(conn->bio);
	SSL_CTX_free(conn->ssl_ctx);
	free(conn);
}

int cast_ssl_connection_get_fd(struct cast_ssl_connection *conn)
{
	long status;
	int fd;

	status = BIO_get_fd(conn->bio, &fd);
	if (status < 0) {
		print_all_ssl_errors();
		return -CAST_ESSL;
	}

	return fd;
}

ssize_t cast_ssl_full_read(struct cast_ssl_connection *conn,
			   void *buf, size_t expected)
{
	ssize_t status;
	int retry = 5;

	if (expected > INT_MAX)
		return -CAST_EINVAL;

	for (;;) {
		status = BIO_read(conn->bio, buf, expected);
		if (status != (ssize_t)expected) {
			if (retry-- && BIO_should_retry(conn->bio))
				continue;

			print_all_ssl_errors();
			status = -CAST_ESSL;
			break;
		}

		break;
	}

	return status;
}

ssize_t cast_ssl_full_write(struct cast_ssl_connection *conn,
			    const void *buf, size_t bufsize)
{
	ssize_t status;
	int retry = 5;

	if (bufsize > INT_MAX)
		return -CAST_EINVAL;

	for (;;) {
		status = BIO_write(conn->bio, buf, bufsize);
		if (status != (ssize_t)bufsize) {
			if (retry-- && BIO_should_retry(conn->bio))
				continue;

			print_all_ssl_errors();
			status = -CAST_ESSL;
			break;
		}

		break;
	}

	return status;
}
