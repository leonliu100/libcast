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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "castdctl.pb-c.h"

#define NORETURN	__attribute__((noreturn))
#define UNUSED		__attribute__((unused))

#define SUN_PATH_MAX	(sizeof(((struct sockaddr_un *)0)->sun_path))
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(*(x)))

static const char *const castd_sock_dir = "/tmp/.castd.sock";

static const struct option longopts[] = {
	{ "version",	no_argument,		NULL,	'v'	},
	{ "help",	no_argument,		NULL,	'h'	},
	{ "name",	required_argument,	NULL,	'n'	},
	{ NULL,		0,			NULL,	0	},
};

static const char *const optstr = "+vhn:";

NORETURN static void print_version(void)
{
	printf("castctl (libcast) %s\n", VERSION);
	printf("Copyright (C) 2016 Bartosz Golaszewski\n");

	exit(EXIT_SUCCESS);
}

NORETURN static void err_msg_and_die(const char *progname,
				     const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);

	exit(EXIT_FAILURE);
}

struct ctl_command {
	const char *name;
	int (*func)(int, int, char **);
	const char *usage;
	const char *help;
};

static int cmd_status_main(int sock, int argc UNUSED, char **argv UNUSED)
{
	CastdCtlRequest req = CASTD_CTL_REQUEST__INIT;
	CastdCtlResponse *resp;
	uint32_t len, lenbuf;
	uint8_t *buf;
	ssize_t status;

	req.type = CASTD_CTL_REQUEST__TYPE__STATUS;
	len = castd_ctl_request__get_packed_size(&req);

	buf = malloc(len);
	if (!buf)
		return -1;

	castd_ctl_request__pack(&req, buf);

	lenbuf = htonl(len);
	status = write(sock, &lenbuf, sizeof(lenbuf));
	if (status != sizeof(lenbuf))
		return -1;

	status = write(sock, buf, len);
	if (status != len)
		return -1;

	status = read(sock, &lenbuf, sizeof(lenbuf));
	if (status != sizeof(lenbuf))
		return -1;

	len = ntohl(lenbuf);
	buf = realloc(buf, len);
	if (!buf)
		return -1;

	status = read(sock, buf, len);
	if (status != len)
		return -1;

	resp = castd_ctl_response__unpack(NULL, len, buf);
	if (!resp)
		return -1;

	printf("status %d\n", resp->type);

	castd_ctl_response__free_unpacked(resp, NULL);

	return 0;
}
static struct ctl_command cmd_status = {
	.name = "status",
	.func = &cmd_status_main,
	.usage = NULL,
	.help = "retrieve the cast daemon status info",
};

static struct ctl_command *cmd_list[] = {
	&cmd_status,
};

static int cmd_list_compar(const void *p1, const void *p2)
{
	const struct ctl_command *cmd1 = *(const struct ctl_command **)p1;
	const struct ctl_command *cmd2 = *(const struct ctl_command **)p2;

	return strcmp(cmd1->name, cmd2->name);
}

NORETURN static void print_help(void)
{
	struct ctl_command *cmd;
	unsigned int i;

	printf("Usage: castctl [OPTIONS] COMMAND ...\n\n");
	printf("Options:\n");
	printf("\t-v, --version:\t\tprint version\n");
	printf("\t-h, --help:\t\tprint this message and exit\n");
	printf("\t-n, --name=NAME\t\tspecify the daemon to connect to by its chromecast's name\n");
	printf("\n");
	printf("Commands:\n");

	for (i = 0; i < ARRAY_SIZE(cmd_list); i++) {
		cmd = cmd_list[i];
		printf("  %s %s\n", cmd->name, cmd->usage ? cmd->usage : "");
		printf("    %s\n", cmd->help);
	}

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	char *castd_name = NULL, *progname = argv[0];
	int opt_ind, opt_char, sock, status;
	struct ctl_command key, *kptr;
	struct sockaddr_un srv_addr;
	char dpath[SUN_PATH_MAX];
	unsigned int numsock = 0;
	struct ctl_command *cmd;
	struct dirent *dentry;
	void *search_res;
	DIR *dirfd;

	qsort(cmd_list, ARRAY_SIZE(cmd_list),
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
		case 'n':
			castd_name = optarg;
			break;
		case '?':
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	if (optind >= argc)
		err_msg_and_die(progname, "command must be specified");

	argc -= optind;
	argv += optind;

	if (castd_name) {
		snprintf(dpath, SUN_PATH_MAX,
			 "%s/%s", castd_sock_dir, castd_name);
	} else {
		dirfd = opendir(castd_sock_dir);
		if (!dirfd) {
			if (errno == ENOENT)
				err_msg_and_die(progname,
						"no cast daemons running");

			err_msg_and_die(progname, "error opening %s: %s",
					castd_sock_dir, strerror(errno));
		}

		for (;;) {
			dentry = readdir(dirfd);
			if (!dentry)
				break;

			if ((strcmp(dentry->d_name, ".") != 0
			    && (strcmp(dentry->d_name, "..") != 0))) {
				numsock++;
				/*
				 * Store the name. If there is only one castd
				 * daemon running, we won't have to go through
				 * the directory again.
				 */
				castd_name = dentry->d_name;
			}
		}
		rewinddir(dirfd);

		if (numsock == 0) {
			closedir(dirfd);
			err_msg_and_die(progname, "no cast daemons running");
		} else if (numsock == 1) {
			snprintf(dpath, SUN_PATH_MAX,
				 "%s/%s", castd_sock_dir, castd_name);
		} else {
			fprintf(stderr, "multiple cast daemons detected:\n");
			for (;;) {
				dentry = readdir(dirfd);
				if (!dentry)
					break;

				if ((strcmp(dentry->d_name, ".") == 0
				    || (strcmp(dentry->d_name, "..") == 0)))
					continue;

				fprintf(stderr, "  %s\n", dentry->d_name);
			}
			fprintf(stderr, "name must be specified\n");

			return EXIT_FAILURE;
		}

		closedir(dirfd);
	}

	key.name = argv[0];
	kptr = &key;
	search_res = bsearch(&kptr, cmd_list, ARRAY_SIZE(cmd_list),
			     sizeof(struct ctl_command *), cmd_list_compar);
	if (!search_res)
		err_msg_and_die(progname, "unsupported command: %s", argv[0]);

	cmd = *(struct ctl_command **)search_res;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		err_msg_and_die(progname, "socket error: %s", strerror(errno));

	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, dpath, SUN_PATH_MAX);

	status = connect(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (status < 0) {
		close(sock);
		err_msg_and_die(progname,
				"connection error: %s", strerror(errno));
	}

	status = cmd->func(sock, argc, argv);

	close(sock);

	return status;
}

