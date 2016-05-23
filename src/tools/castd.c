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
	{ "no-ping",	no_argument,		NULL,	'p'	},
	{ "log-level",	required_argument,	NULL,	'l'	},
	{ NULL,		0,			NULL,	0	},
};

static const char *const optstr = "vhd:pl:";

struct log_level {
	int val;
	const char *str;
};
#define LOG_INVAL INT_MAX

/* Shorter names for library log levels. */
enum {
	LOG_NONE = CAST_LOG_NONE,
	LOG_ERR = CAST_LOG_ERR,
	LOG_WARN = CAST_LOG_WARN,
	LOG_INFO = CAST_LOG_INFO,
	LOG_DEBUG = CAST_LOG_DBG,
	LOG_DUMP = CAST_LOG_DUMP,
};

static struct log_level log_levels[] = {
	{
		.val = CAST_LOG_NONE,
		.str = "NONE",
	},
	{
		.val = CAST_LOG_ERR,
		.str = "ERROR",
	},
	{
		.val = CAST_LOG_WARN,
		.str = "WARN",
	},
	{
		.val = CAST_LOG_INFO,
		.str = "INFO",
	},
	{
		.val = CAST_LOG_DBG,
		.str = "DEBUG",
	},
	{
		.val = CAST_LOG_DUMP,
		.str = "DUMP",
	}
};

static int parse_log_level(const char *name)
{
	unsigned int i;

	for (i = 0; i < CAST_ARRAY_SIZE(log_levels); i++) {
		if (strcmp(name, log_levels[i].str) == 0)
			return log_levels[i].val;
	}

	return LOG_INVAL;
}

static const char * log_level_name(int level)
{
	unsigned int i;

	for (i = 0; i < CAST_ARRAY_SIZE(log_levels); i++) {
		if (level == log_levels[i].val)
			return log_levels[i].str;
	}

	return "INVALID";
}

enum {
	CASTD_STATUS_OK = 0,
	CASTD_STATUS_DEFUNCT,
};

struct castd_context {
	cast_connection *cast_conn;
	int ctl_sock;
	int log_level;
	int run;
	int status;
};
#define CASTD_CTX_INITIALIZER	{ NULL, 0, CAST_LOG_WARN, 1, CASTD_STATUS_OK }

static void log_msg(struct castd_context *ctx, int level, const char *fmt, ...)
{
	va_list va;

	if (level <= ctx->log_level) {
		va_start(va, fmt);
		fprintf(stderr, "castd [%s]\t", log_level_name(level));
		vfprintf(stderr, fmt, va);
		fprintf(stderr, "\n");
		va_end(va);
	}
}

static void lib_log_callback(int level, const char *msg, void *priv)
{
	log_msg((struct castd_context *)priv, level, msg);
}

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
	printf("\t-p, --no-ping\t\tdon't actively keep the connection alive - just respond to pings\n");
	printf("\t-l, --log-level={DUMP|DEBUG|INFO|WARN|ERROR|NONE}\n");
	printf("\t\t\t\t\tspecify the log level (default: warning)\n");

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

static void handle_heartbeat_msg(struct castd_context *ctx, cast_message *msg)
{
	int type, status;

	type = cast_payload_type_get(cast_msg_payload_get(msg));

	switch (type) {
	case CAST_PAYLOAD_PING:
		log_msg(ctx, LOG_DEBUG, "ping request received");
		status = cast_msg_pong_respond(ctx->cast_conn, msg);
		if (status != CAST_OK) {
			log_msg(ctx, LOG_ERR,
				"error responding to ping request: %s",
				cast_strerror(status));
		} else {
			log_msg(ctx, LOG_DEBUG, "pong request sent");
		}
		break;
	case CAST_PAYLOAD_PONG:
		/* TODO Detect broken connections. */
		log_msg(ctx, LOG_DEBUG, "pong response received");
		break;
	default:
		log_msg(ctx, LOG_WARN, "dropping unknown heartbeat message");
	}
}

static void handle_cast_message(struct castd_context *ctx)
{
	cast_message *msg;
	int ns;

	msg = cast_conn_msg_recv(ctx->cast_conn);
	if (CAST_IS_ERR(msg)) {
		log_msg(ctx, LOG_ERR, "error receiving message: %s",
			cast_strerror(CAST_PTR_ERR(msg)));
		return;
	}

	ns = cast_msg_namespace_get(msg);

	switch (ns) {
	case CAST_MSG_NS_HEARTBEAT:
		handle_heartbeat_msg(ctx, msg);
		break;
	default:
		log_msg(ctx, LOG_WARN,
			"dropping message from unknown namespace");
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

static void handle_ctl_request(struct castd_context *ctx)
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

	sock = accept(ctx->ctl_sock, (struct sockaddr *)&addr, &socklen);
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
	int opt_ind, opt_char, status, ping = 1, numfds = NUM_PFDS;
	struct castd_context ctx = CASTD_CTX_INITIALIZER;
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
		case 'p':
			ping = 0;
			break;
		case 'l':
			ctx.log_level = parse_log_level(optarg);
			if (ctx.log_level == LOG_INVAL) {
				err_msg_and_die(argv[0],
						"invalid log level: %s\n",
						optarg);
			}
			break;
		case '?':
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	cast_log_callback_set(lib_log_callback, &ctx);

	if (optind != (argc-1))
		err_msg_and_die(argv[0], "friendly name must be specified\n");

	snprintf(hostname, sizeof(hostname), "%s.%s",
		 argv[optind], domain ? domain : "local");

	ctx.ctl_sock = create_ctl_socket(hostname);
	if (ctx.ctl_sock < 0) {
		err_msg_and_die(argv[0],
				"cannot establish control socket: %s\n",
				strerror(errno));
	}

	ctx.cast_conn = cast_conn_connect(hostname);
	if (CAST_IS_ERR(ctx.cast_conn)) {
		close(pfds[CTL_PFD].fd);
		err_msg_and_die(argv[0], "cast connection error: %s\n",
				cast_strerror(CAST_PTR_ERR(ctx.cast_conn)));
	}

	pfds[CTL_PFD].fd = ctx.ctl_sock;
	pfds[CAST_PFD].fd = cast_conn_fd_get(ctx.cast_conn);
	pfds[CAST_PFD].events = pfds[CTL_PFD].events = POLLIN | POLLPRI;

	/* TODO This is where we should daemonize. */

	while (ctx.run) {
		status = poll(pfds, numfds, 5000 /* 5 seconds */);
		if (status < 0) {
			log_msg(&ctx, LOG_ERR,
				"poll error: %s, aborting", strerror(errno));
			abort();
		} else if (status > 0) {
			if (pfds[CAST_PFD].revents)
				handle_cast_message(&ctx);
			else if (pfds[CTL_PFD].revents)
				handle_ctl_request(&ctx);
		} else {
			/*
			 * Timeout - send the keep-alive message unless we
			 * were told not to.
			 */
			if (ping) {
				status = cast_msg_ping_send(ctx.cast_conn);
				if (status != CAST_OK) {
					log_msg(&ctx, LOG_ERR,
						"error sending ping request: %s",
						cast_strerror(status));
				} else {
					log_msg(&ctx, LOG_DEBUG,
						"ping request sent");
				}
			}
		}

		/*
		 * The DEFUNCT status means that the connection to chromecast
		 * was broken. We still continue to listen for client requests,
		 * but won't be able to send any more messages to chromecast.
		 *
		 * We want to let the user query the daemon status and request
		 * us to quit manually - because of that we don't abort on our
		 * own.
		 */
		if (ctx.status == CASTD_STATUS_DEFUNCT)
			numfds--;
	}

	cast_conn_close(ctx.cast_conn);
	close(ctx.ctl_sock);

	return EXIT_SUCCESS;
}
