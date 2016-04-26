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
#include <getopt.h>
#include <errno.h>
#include <poll.h>

static const struct option longopts[] = {
	{ "version",	no_argument,		NULL,	'v'	},
	{ "help",	no_argument,		NULL,	'h'	},
	{ "domain",	required_argument,	NULL,	'r'	},
	{ NULL,		0,			NULL,	0	},
};

static const char *const optstr = "vhr:";

CAST_NORETURN static void print_version(void)
{
	printf("castd (libcast) %s\n", cast_version_str());
	printf("Copyright (C) 2016 Bartosz Golaszewski\n");

	exit(EXIT_SUCCESS);
}

CAST_NORETURN static void print_help(void)
{
	printf("Usage: lscast [OPTIONS] FRIENDLY_NAME\n\n");
	printf("Options:\n");
	printf("\t-v, --version:\t\tprint version\n");
	printf("\t-h, --help:\t\tprint this message and exit\n");
	printf("\t-d, --domain=DOMAIN\tspecify the domain name (defaults to 'local')\n");

	exit(EXIT_SUCCESS);
}

static void handle_cast_message(struct cast_connection *conn)
{
	struct cast_message *msg;

	msg = cast_msg_receive(conn);
	if (CAST_IS_ERR(msg)) {
		fprintf(stderr, "error receiving message: %s\n",
			cast_strerror(CAST_PTR_ERR(msg)));
	}
}

int main(int argc, char **argv)
{
	struct cast_connection *cast_conn;
	int opt_ind, opt_char, status;
	struct pollfd pfds[1];
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

	if (argc != 2) {
		fprintf(stderr, "friendly name must be specified\n");
		return EXIT_FAILURE;
	}

	snprintf(hostname, sizeof(hostname), "%s.%s",
		 argv[1], domain ? domain : "local");

	cast_conn = cast_connect(hostname);
	if (CAST_IS_ERR(cast_conn)) {
		fprintf(stderr, "connection error: %s\n",
			cast_strerror(CAST_PTR_ERR(cast_conn)));
		return EXIT_FAILURE;
	}

	pfds[0].fd = cast_connection_get_fd(cast_conn);
	pfds[0].events = POLLIN | POLLPRI;

	for (;;) {
		status = poll(pfds, 1, 5000);
		if (status < 0) {
			fprintf(stderr, "poll error: %s\n", strerror(errno));
			break;
		} else if (status > 0) {
			if (pfds[0].revents) {
				handle_cast_message(cast_conn);
			}
		} else {
			cast_send_ping(cast_conn);
		}
	}

	cast_close_connection(cast_conn);

	return EXIT_SUCCESS;
}
