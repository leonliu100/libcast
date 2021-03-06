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
	int run;
	int status;
	int last_reqid;
	struct cast_list_head deferred_requests;
};
#define CASTD_CTX_INITIALIZER \
	{ NULL, 0, 1, CASTD_STATUS_OK, 1, { NULL, NULL } }

struct deferred_request {
	struct cast_list_head link;
	int reqid;
};

static int log_level = LOG_WARN;

static void log_msg(int level, const char *fmt, ...)
{
	va_list va;

	if (level <= log_level) {
		va_start(va, fmt);
		fprintf(stderr, "castd [%s]\t", log_level_name(level));
		vfprintf(stderr, fmt, va);
		fprintf(stderr, "\n");
		va_end(va);
	}
}

static void lib_log_callback(int level,
			     const char *msg, void *priv CAST_UNUSED)
{
	log_msg(level, msg);
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

static int ctx_get_new_reqid(struct castd_context *ctx)
{
	if (ctx->last_reqid == INT_MAX)
		ctx->last_reqid = 1;

	return ctx->last_reqid++;
}

static void handle_heartbeat_msg(struct castd_context *ctx, cast_message *msg)
{
	int type, status;

	type = cast_payload_type_get(cast_msg_payload_get(msg));

	switch (type) {
	case CAST_PAYLOAD_PING:
		log_msg(LOG_DEBUG, "ping request received");
		status = cast_msg_pong_respond(ctx->cast_conn, msg);
		if (status != CAST_OK) {
			log_msg(LOG_ERR,
				"error responding to ping request: %s",
				cast_strerror(status));
		} else {
			log_msg(LOG_DEBUG, "pong request sent");
		}
		break;
	case CAST_PAYLOAD_PONG:
		/* TODO Detect broken connections. */
		log_msg(LOG_DEBUG, "pong response received");
		break;
	default:
		log_msg(LOG_WARN, "dropping unknown heartbeat message");
	}
}

static void handle_cast_message(struct castd_context *ctx)
{
	cast_message *msg;
	int ns;

	msg = cast_conn_msg_recv(ctx->cast_conn);
	if (CAST_IS_ERR(msg)) {
		if (CAST_PTR_ERR(msg) == -CAST_ECONNCLOSED) {
			log_msg(LOG_ERR, "connection closed by chromecast");
			ctx->status = CASTD_STATUS_DEFUNCT;
			return;
		}
		log_msg(LOG_ERR, "error receiving message: %s",
			cast_strerror(CAST_PTR_ERR(msg)));
		return;
	}

	ns = cast_msg_namespace_get(msg);

	switch (ns) {
	case CAST_MSG_NS_HEARTBEAT:
		handle_heartbeat_msg(ctx, msg);
		break;
	default:
		log_msg(LOG_WARN, "dropping message from unknown namespace");
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

struct ctl_command {
	const char *name;
	int request_type;
	int response_type;
	int (*handler)(CastdCtlRequest *,
		       CastdCtlResponse *, struct castd_context *);
	void (*resp_cleanup)(CastdCtlResponse *, struct castd_context *);
};

#define CTL_CMD_OK		0
#define CTL_CMD_DEFERRED	1

static int cmd_status_handler(CastdCtlRequest *req CAST_UNUSED,
			      CastdCtlResponse *resp,
			      struct castd_context *ctx CAST_UNUSED)
{
	resp->status = malloc(sizeof(CastdCtlStatusResp));
	if (!resp->status)
		return -CASTD_CTL_ERROR_RESP__CODE__ENOMEM;

	castd_ctl_status_resp__init(resp->status);
	if (ctx->status == CASTD_STATUS_OK)
		resp->status->status = CASTD_CTL_STATUS_RESP__VALUE__OK;
	else
		resp->status->status = CASTD_CTL_STATUS_RESP__VALUE__DEFUNCT;

	return CTL_CMD_OK;
}

static void cmd_status_resp_cleanup(CastdCtlResponse *resp,
				    struct castd_context *ctx CAST_UNUSED)
{
	if (resp->status)
		free(resp->status);
}

static struct ctl_command cmd_status = {
	.name = "status",
	.request_type = CASTD_CTL_REQUEST__TYPE__STATUS,
	.response_type = CASTD_CTL_RESPONSE__TYPE__STATUS,
	.handler = cmd_status_handler,
	.resp_cleanup = cmd_status_resp_cleanup,
};

static int cmd_quit_handler(CastdCtlRequest *req CAST_UNUSED,
			    CastdCtlResponse *resp CAST_UNUSED,
			    struct castd_context *ctx)
{
	ctx->run = 0;

	return CTL_CMD_OK;
}

static struct ctl_command cmd_quit = {
	.name = "quit",
	.request_type = CASTD_CTL_REQUEST__TYPE__QUIT,
	.response_type = CASTD_CTL_RESPONSE__TYPE__QUIT,
	.handler = cmd_quit_handler,
};

static int cmd_app_handler(CastdCtlRequest *req CAST_UNUSED,
			   CastdCtlResponse *resp CAST_UNUSED,
			   struct castd_context *ctx)
{
	int status, reqid;

	reqid = ctx_get_new_reqid(ctx);

	status = cast_msg_get_status_send(ctx->cast_conn, reqid);
	if (status != CAST_OK) {
		log_msg(LOG_ERR, "error sending GET_STATUS request: %s",
			cast_strerror(status));
		return -CASTD_CTL_ERROR_RESP__CODE__EPROTO;
	}

	return CTL_CMD_OK;
}

static struct ctl_command cmd_app = {
	.name = "app",
	.request_type = CASTD_CTL_REQUEST__TYPE__APP,
	.response_type = CASTD_CTL_RESPONSE__TYPE__APP,
	.handler = cmd_app_handler,
};

static struct ctl_command *ctl_cmds[] = {
	&cmd_status,
	&cmd_quit,
	&cmd_app,
};

static int cmd_list_compar(const void *p1, const void *p2)
{
	const struct ctl_command *cmd1 = *(const struct ctl_command **)p1;
	const struct ctl_command *cmd2 = *(const struct ctl_command **)p2;

	if (cmd1->request_type > cmd2->request_type)
		return 1;
	else if (cmd1->request_type < cmd2->request_type)
		return -1;
	else
		return 0;
}

static struct ctl_command * find_command(int request_type)
{
	struct ctl_command key, *keyptr;
	void *search_res;

	key.request_type = request_type;
	keyptr = &key;
	search_res = bsearch(&keyptr, ctl_cmds, CAST_ARRAY_SIZE(ctl_cmds),
			     sizeof(struct ctl_command *), cmd_list_compar);
	if (!search_res)
		return NULL;

	return *(struct ctl_command **)search_res;
}

static ssize_t ctl_recv_full(int fd, void *buf, size_t bufsize, int flags)
{
	int recvd;

	recvd = recv(fd, buf, bufsize, flags);
	if (recvd < 0) {
		log_msg(LOG_ERR,
			"error receiving message: %s", strerror(errno));
		close(fd);
		return -1;
	} else if (recvd == 0) {
		log_msg(LOG_INFO,
			"connection closed by client");
		close(fd);
		return -1;
	} else if ((size_t)recvd != bufsize) {
		log_msg(LOG_WARN,
			"dropping incomplete client message");
		close(fd);
		return -1;
	}

	return 0;
}

static void handle_ctl_request(struct castd_context *ctx)
{
	struct ctl_command *cmd;
	struct sockaddr_un addr;
	socklen_t socklen = 0;
	int sock, retval;
	ssize_t status;
	uint32_t hdr;
	uint8_t *buf;
	size_t len;

	CastdCtlRequest *req;
	CastdCtlResponse resp = CASTD_CTL_RESPONSE__INIT;
	CastdCtlErrorResp eresp = CASTD_CTL_ERROR_RESP__INIT;

	sock = accept(ctx->ctl_sock, (struct sockaddr *)&addr, &socklen);
	if (sock < 0) {
		log_msg(LOG_ERR, "error accepting client connection: %s",
			strerror(errno));
		return;
	}

	status = ctl_recv_full(sock, &hdr, sizeof(hdr), 0);
	if (status < 0)
		return;

	len = ntohl(hdr);
	buf = malloc(len);
	if (!buf) {
		log_msg(LOG_ERR, "out of memory");
		close(sock);
		return;
	}

	status = ctl_recv_full(sock, buf, len, MSG_DONTWAIT);
	if (status < 0) {
		free(buf);
		return;
	}

	req = castd_ctl_request__unpack(NULL, len, buf);
	free(buf);
	if (!req) {
		log_msg(LOG_ERR, "error unpacking client message");
		close(sock);
		return;
	}

	cmd = find_command(req->type);
	if (!cmd) {
		eresp.code = CASTD_CTL_ERROR_RESP__CODE__ENOSUPP;
		resp.type = CASTD_CTL_RESPONSE__TYPE__ERROR;
		resp.error = &eresp;
		goto send_resp;
	}

	log_msg(LOG_DEBUG, "control request '%s' received", cmd->name);

	retval = cmd->handler(req, &resp, ctx);
	castd_ctl_request__free_unpacked(req, NULL);
	if (retval != CTL_CMD_OK) {
		eresp.code = abs(retval);
		resp.type = CASTD_CTL_RESPONSE__TYPE__ERROR;
		resp.error = &eresp;
		goto send_resp;
	}

	resp.type = cmd->response_type;

send_resp:
	len = castd_ctl_response__get_packed_size(&resp);
	hdr = htonl(len);

	buf = malloc(len + sizeof(hdr));
	if (!buf) {
		log_msg(LOG_ERR,
			"out of memory - cannot send response to client");
		if (cmd && cmd->resp_cleanup)
			cmd->resp_cleanup(&resp, ctx);
		close(sock);
		return;
	}

	memcpy(buf, &hdr, sizeof(hdr));
	castd_ctl_response__pack(&resp, buf + sizeof(hdr));

	status = send(sock, buf, len + sizeof(hdr), MSG_DONTWAIT);
	free(buf);
	if (status < 0) {
		log_msg(LOG_ERR,
			"error sending response: %s", strerror(errno));
	} else if ((size_t)status != (len + sizeof(hdr))) {
		log_msg(LOG_WARN, "sending response: incomplete message sent");
	}

	if (cmd && cmd->resp_cleanup)
		cmd->resp_cleanup(&resp, ctx);
	close(sock);

	return;
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

	qsort(ctl_cmds, CAST_ARRAY_SIZE(ctl_cmds),
	      sizeof(struct ctl_command *), cmd_list_compar);

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
			log_level = parse_log_level(optarg);
			if (log_level == LOG_INVAL) {
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
	cast_list_head_init(&ctx.deferred_requests);

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
			log_msg(LOG_ERR,
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
					log_msg(LOG_ERR,
						"error sending ping request: %s",
						cast_strerror(status));
				} else {
					log_msg(LOG_DEBUG,
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
			numfds = 1;

		pfds[CAST_PFD].revents = pfds[CTL_PFD].revents = 0;
	}

	cast_conn_close(ctx.cast_conn);
	close(ctx.ctl_sock);

	return EXIT_SUCCESS;
}
