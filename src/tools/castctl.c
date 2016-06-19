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
#define INIT_FUNC	__attribute__((constructor))
#define PACKED		__attribute__((packed))

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

static char *progname = "castctl";

NORETURN static void print_version(void)
{
	printf("castctl (libcast) %s\n", VERSION);
	printf("Copyright (C) 2016 Bartosz Golaszewski\n");

	exit(EXIT_SUCCESS);
}

static void err_msg(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, va);
	va_end(va);
}

NORETURN static void err_msg_and_die(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, va);
	va_end(va);

	exit(EXIT_FAILURE);
}

struct msg_buf {
	uint32_t size;
	uint8_t buf[0];
} PACKED;

/*
 * This structure describes a single castctl command that can be used to
 * control the cast daemon.
 *
 * The usage, prepare_request and handle_response fields are not mandatory.
 *
 * The name of the command must be unique.
 */
struct ctl_command {
	const char *name;
	int request_type;
	int response_type;
	int (*prepare_request)(CastdCtlRequest *, int, char **);
	int (*handle_response)(CastdCtlResponse *);
	const char *usage;
	const char *help;
};

static int cmd_status_handle_resp(CastdCtlResponse *resp)
{
	char *status;

	switch (resp->status->status) {
	case CASTD_CTL_STATUS_RESP__VALUE__OK:
		status = "OK";
		break;
	case CASTD_CTL_STATUS_RESP__VALUE__DEFUNCT:
		status = "DEFUNCT";
		break;
	default:
		status = "UNKNOWN";
	}

	printf("castd status: %s\n", status);

	return 0;
}

static struct ctl_command cmd_status = {
	.name = "status",
	.request_type = CASTD_CTL_REQUEST__TYPE__STATUS,
	.response_type = CASTD_CTL_RESPONSE__TYPE__STATUS,
	.handle_response = cmd_status_handle_resp,
	.help = "retrieve the cast daemon status info",
};

static struct ctl_command cmd_quit = {
	.name = "quit",
	.request_type = CASTD_CTL_REQUEST__TYPE__QUIT,
	.response_type = CASTD_CTL_RESPONSE__TYPE__QUIT,
	.help = "request the cast daemon to quit",
};

static int cmd_app_handle_resp(CastdCtlResponse *resp)
{
	printf("current chromecast app: %s\n", resp->app->name);

	return 0;
}

static struct ctl_command cmd_app = {
	.name = "app",
	.request_type = CASTD_CTL_REQUEST__TYPE__APP,
	.response_type = CASTD_CTL_RESPONSE__TYPE__APP,
	.handle_response = cmd_app_handle_resp,
	.help = "get the name of currently running app",
};

static struct ctl_command *cmd_list[] = {
	&cmd_status,
	&cmd_quit,
	&cmd_app,
};

static int cmd_list_compar(const void *p1, const void *p2)
{
	const struct ctl_command *cmd1 = *(const struct ctl_command **)p1;
	const struct ctl_command *cmd2 = *(const struct ctl_command **)p2;

	return strcmp(cmd1->name, cmd2->name);
}

/* We sort the command list by name when the program starts. */
INIT_FUNC static void sort_command_list(void)
{
	qsort(cmd_list, ARRAY_SIZE(cmd_list),
	      sizeof(struct ctl_command *), cmd_list_compar);
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

static int is_socket(const char *file)
{
	struct stat statbuf;
	int status;
	char *path;

	path = malloc(strlen(castd_sock_dir) + strlen(file) + 2);
	if (!path)
		err_msg_and_die("out of memory\n");

	sprintf(path, "%s/%s", castd_sock_dir, file);

	status = stat(path, &statbuf);
	free(path);
	if (status < 0)
		err_msg_and_die("stat error: %s\n", strerror(errno));

	return S_ISSOCK(statbuf.st_mode);

}

static void find_castd_sock(char *sockpath_buf)
{
	unsigned int numsock = 0;
	struct dirent *dentry;
	char *castd_name;
	DIR *dirfd;

	/*
	 * The user didn't give us the name of the chromecast, so we need
	 * to figure out the daemon ourselves.
	 */
	dirfd = opendir(castd_sock_dir);
	if (!dirfd) {
		if (errno == ENOENT)
			err_msg_and_die("no cast daemons running\n");

		err_msg_and_die("error opening %s: %s\n",
				castd_sock_dir, strerror(errno));
	}

	/* Count the unix domain sockets in the castd socket directory. */
	for (;;) {
		dentry = readdir(dirfd);
		if (!dentry)
			break;

		if (is_socket(dentry->d_name)) {
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
		err_msg_and_die("no cast daemons running\n");
	} else if (numsock == 1) {
		/* There's only one socket, so let's return it. */
		snprintf(sockpath_buf, SUN_PATH_MAX,
			 "%s/%s", castd_sock_dir, castd_name);
	} else {
		/*
		 * If there are more daemons running, the user must point us
		 * to the right one.
		 */
		err_msg("multiple cast daemons detected:\n");
		for (;;) {
			dentry = readdir(dirfd);
			if (!dentry)
				break;

			if (!is_socket(dentry->d_name))
				continue;

			fprintf(stderr, "  %s\n", dentry->d_name);
		}
		err_msg_and_die("name must be specified\n");
	}

	closedir(dirfd);
}

static struct ctl_command * find_command(const char *name)
{
	struct ctl_command key, *keyptr;
	void *search_res;

	key.name = name;
	keyptr = &key;
	search_res = bsearch(&keyptr, cmd_list, ARRAY_SIZE(cmd_list),
			     sizeof(struct ctl_command *), cmd_list_compar);
	if (!search_res)
		return NULL;

	return *(struct ctl_command **)search_res;
}

static void handle_error_response(const char *cmd, CastdCtlResponse *resp)
{
	switch (resp->error->code) {
	case CASTD_CTL_ERROR_RESP__CODE__ENOSUPP:
		err_msg_and_die("%s: command unsupported by castd\n", cmd);
	default:
		err_msg_and_die("unknown error returned by castd\n");
	}
}

int main(int argc, char **argv)
{
	int opt_ind, opt_char, sock, status;
	struct sockaddr_un srv_addr;
	char sockpath[SUN_PATH_MAX];
	struct ctl_command *cmd;
	char *castd_name = NULL;
	struct msg_buf *msg;
	ssize_t iores;
	uint32_t len;

	CastdCtlRequest request = CASTD_CTL_REQUEST__INIT;
	CastdCtlResponse *response;

	progname = argv[0];

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
		err_msg_and_die("command must be specified\n");

	argc -= optind;
	argv += optind;

	if (castd_name) {
		snprintf(sockpath, SUN_PATH_MAX,
			 "%s/%s", castd_sock_dir, castd_name);
	} else {
		find_castd_sock(sockpath);
	}

	cmd = find_command(argv[0]);
	if (!cmd)
		err_msg_and_die("unsupported command: %s\n", argv[0]);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		err_msg_and_die("socket error: %s\n", strerror(errno));

	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, sockpath, SUN_PATH_MAX);

	status = connect(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (status < 0)
		err_msg_and_die("connection error: %s\n", strerror(errno));

	request.type = cmd->request_type;
	if (cmd->prepare_request) {
		status = cmd->prepare_request(&request, argc, argv);
		if (status < 0)
			err_msg_and_die("error preparing the request\n");
	}

	len = castd_ctl_request__get_packed_size(&request);

	msg = malloc(len + sizeof(msg->size));
	if (!msg)
		err_msg_and_die("out of memory\n");

	msg->size = htonl(len);
	castd_ctl_request__pack(&request, msg->buf);

	iores = send(sock, (void *)msg, len + sizeof(msg->size), MSG_DONTWAIT);
	if (iores < 0)
		err_msg_and_die("sending message: %s\n", strerror(errno));
	else if (iores != (ssize_t)(len + sizeof(msg->size)))
		err_msg_and_die("unable to send whole message\n");

	iores = recv(sock, &msg->size, sizeof(msg->size), 0);
	if (iores < 0)
		err_msg_and_die("receiving message: %s\n", strerror(errno));
	else if (iores == 0)
		err_msg_and_die("connection closed by castd\n");
	else if (iores != sizeof(msg->size))
		err_msg_and_die("didn't receive the whole message header\n");

	len = ntohl(msg->size);

	msg = realloc(msg, len + sizeof(msg->size));
	if (!msg)
		err_msg_and_die("out of memory\n");

	iores = recv(sock, msg->buf, len, MSG_DONTWAIT);
	if (iores < 0)
		err_msg_and_die("receiving message: %s\n", strerror(errno));
	else if (iores == 0)
		err_msg_and_die("connection closed by castd\n");
	else if (iores != len)
		err_msg_and_die("didn't receive the whole message\n");

	response = castd_ctl_response__unpack(NULL, len, msg->buf);
	if (!response)
		err_msg_and_die("out of memory\n");

	if (response->type == CASTD_CTL_RESPONSE__TYPE__ERROR)
		handle_error_response(cmd->name, response);
	else if (response->type != cmd->response_type)
		err_msg_and_die("received message of invalid type\n");

	if (cmd->handle_response)
		status = cmd->handle_response(response);

	free(msg);
	castd_ctl_response__free_unpacked(response, NULL);
	close(sock);

	return EXIT_SUCCESS;
}

