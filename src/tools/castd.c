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

#include <libcast.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "castdctl.pb-c.h"

static const char *const ctl_sock_dir = "/tmp/.castd.sock";

static const struct option longopts[] = {
	{ "version",	no_argument,		NULL,	'v'	},
	{ "help",	no_argument,		NULL,	'h'	},
	{ "domain",	required_argument,	NULL,	'd'	},
	{ NULL,		0,			NULL,	0	},
};

static const char *const optstr = "vhd:";

CAST_NORETURN static void print_version(void)
{
	printf("castd (libcast) %s\n", cast_version_str());
	printf("Copyright (C) 2016 Bartosz Golaszewski\n");

	exit(EXIT_SUCCESS);
}

CAST_NORETURN static void print_help(void)
{
	printf("Usage: castd [OPTIONS] FRIENDLY_NAME\n\n");
	printf("Options:\n");
	printf("\t-v, --version:\t\tprint version\n");
	printf("\t-h, --help:\t\tprint this message and exit\n");
	printf("\t-d, --domain=DOMAIN\tspecify the domain name (defaults to 'local')\n");

	exit(EXIT_SUCCESS);
}

CAST_NORETURN static void err_msg_and_die(const char *progname,
					  const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, va);
	va_end(va);

	exit(EXIT_FAILURE);
}

static void handle_cast_message(struct cast_connection *conn)
{
	struct cast_message *msg;

	msg = cast_msg_receive(conn);
	if (CAST_IS_ERR(msg)) {
		fprintf(stderr, "error receiving message: %s\n",
			cast_strerror(CAST_PTR_ERR(msg)));
	}

	cast_msg_free(msg);
}

static int create_ctl_socket(const char *hostname)
{
	struct sockaddr_un addr;
	int sock, status;

	status = mkdir(ctl_sock_dir, 0777);
	if (status && errno != EEXIST)
		return -1;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
		 "%s/%s", ctl_sock_dir, hostname);

	unlink(addr.sun_path);

	status = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (status) {
		close(sock);
		return -1;
	}

	status = listen(sock, 5);
	if (status) {
		close(sock);
		return -1;
	}

	return sock;
}

static void handle_ctl_request(int srv_sock)
{
	CastdCtlRequest *req;
	CastdCtlResponse resp = CASTD_CTL_RESPONSE__INIT;
	CastdCtlStatusResp srestp = CASTD_CTL_STATUS_RESP__INIT;
	ssize_t status;
	uint32_t len, lenbuf;
	uint8_t *buf;
	int sock;
	struct sockaddr_un addr;
	socklen_t socklen;

	sock = accept(srv_sock, (struct sockaddr *)&addr, &socklen);
	if (sock < 0)
		return;

	status = read(sock, &lenbuf, sizeof(lenbuf));
	if (status != sizeof(lenbuf))
		return;

	len = ntohl(lenbuf);
	buf = malloc(len);
	if (!buf)
		return;

	status = read(sock, buf, len);
	if (status != len)
		return;

	req = castd_ctl_request__unpack(NULL, len, buf);
	if (!req)
		return;

	printf("request: %d\n", req->type);

	resp.type = CASTD_CTL_RESPONSE__TYPE__STATUS;
	srestp.status = CASTD_CTL_STATUS_RESP__VALUE__OK;
	resp.status = &srestp;

	len = castd_ctl_response__get_packed_size(&resp);
	buf = realloc(buf, len);
	if (!buf)
		return;

	castd_ctl_response__pack(&resp, buf);

	lenbuf = htonl(len);
	status = write(sock, &lenbuf, sizeof(lenbuf));
	if (status != sizeof(lenbuf))
		return;

	status = write(sock, buf, len);
}

enum {
	CTL_PFD = 0,
	CAST_PFD,
	NUM_PFDS,
};

int main(int argc, char **argv)
{
	struct cast_connection *cast_conn;
	int opt_ind, opt_char, status;
	struct pollfd pfds[NUM_PFDS];
	char *domain = NULL;
	char hostname[256];

	for (;;) {
		opt_char = getopt_long(argc, argv, optstr, longopts, &opt_ind);
		if (opt_char < 0)
			break;

		switch (opt_char) {
		case 'v':
			print_version();
		case 'h':
			print_help();
		case 'd':
			domain = optarg;
			break;
		case '?':
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	if (optind != (argc-1))
		err_msg_and_die(argv[0], "friendly name must be specified\n");

	snprintf(hostname, sizeof(hostname), "%s.%s",
		 argv[optind], domain ? domain : "local");

	pfds[CTL_PFD].fd = create_ctl_socket(hostname);
	if (pfds[CTL_PFD].fd < 0) {
		err_msg_and_die(argv[0],
				"cannot establish control socket: %s\n",
				strerror(errno));
	}

	cast_conn = cast_conn_connect(hostname);
	if (CAST_IS_ERR(cast_conn)) {
		close(pfds[CTL_PFD].fd);
		err_msg_and_die(argv[0], "connection error: %s\n",
				cast_strerror(CAST_PTR_ERR(cast_conn)));
	}

	pfds[CAST_PFD].fd = cast_conn_fd_get(cast_conn);

	pfds[CAST_PFD].events = pfds[CTL_PFD].events = POLLIN | POLLPRI;

	for (;;) {
		status = poll(pfds, NUM_PFDS, 5000);
		if (status < 0) {
			fprintf(stderr, "poll error: %s\n", strerror(errno));
			break;
		} else if (status > 0) {
			if (pfds[CAST_PFD].revents) {
				handle_cast_message(cast_conn);
			} else if (pfds[CTL_PFD].revents) {
				handle_ctl_request(pfds[CTL_PFD].fd);
			}
		} else {
			cast_conn_ping(cast_conn);
		}
	}

	cast_conn_close(cast_conn);

	return EXIT_SUCCESS;
}
