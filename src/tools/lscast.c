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
#include <stdarg.h>
#include <getopt.h>
#include <limits.h>

#define DEFAULT_TIMEOUT 1000

struct callback_data {
	int show_domain;
	int resolve;
	unsigned int found;
	unsigned int max;
};
#define CALLBACK_DATA_INITIALIZER { 0, 0, 0, UINT_MAX }

static const struct option longopts[] = {
	{ "version",		no_argument,		NULL,	'v'	},
	{ "help",		no_argument,		NULL,	'h'	},
	{ "timeout",		required_argument, 	NULL,	't'	},
	{ "max",		required_argument,	NULL,	'm'	},
	{ "show-domain",	no_argument,		NULL,	'd'	},
	{ "resolve",		no_argument,		NULL,	'r'	},
	{ NULL,			0,			NULL,	0	},
};

static const char *const optstr = "vht:m:dr";

CAST_NORETURN static void print_version(void)
{
	printf("lscast (libcast) %s\n", cast_version_str());
	printf("Copyright (C) 2016 Bartosz Golaszewski\n");

	exit(EXIT_SUCCESS);
}

CAST_NORETURN static void print_help(void)
{
	printf("Usage: lscast [OPTIONS]\n\n");
	printf("Options:\n");
	printf("\t-v, --version:\t\tprint version\n");
	printf("\t-h, --help:\t\tprint this message and exit\n");
	printf("\t-t, --timeout=MSEC:\tspecify the timeout (default: %u msec)\n",
	       DEFAULT_TIMEOUT);
	printf("\t-m, --max=NUM:\t\tspecify the maximum number of cast devices to find (default: no limit)\n");
	printf("\t-d, --show-domain:\tprint the domain name\n");
	printf("\t-r, --resolve:\tresolve the name and print the IP address\n");

	exit(EXIT_SUCCESS);
}

static int discovery_callback(const char *name,
			      const char *domain, void *priv)
{
	struct callback_data *data = priv;
	char hostname[256];
	unsigned char *c;
	uint32_t addr;
	int status;

	printf("%s", name);

	if (data->show_domain)
		printf(".%s", domain);

	if (data->resolve) {
		snprintf(hostname, sizeof(hostname), "%s.%s", name, domain);
		status = cast_resolve(hostname, &addr);
		if (status) {
			printf(" [UNKNOWN]");
		} else {
			c = (void *)&addr;
			printf(" [%u.%u.%u.%u]", c[0], c[1], c[2], c[3]);
		}
	}

	printf("\n");

	return ++data->found >= data->max ? CAST_DISCOVER_STOP
					  : CAST_DISCOVER_CONTINUE;
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

int main(int argc, char **argv)
{
	struct callback_data cb_data = CALLBACK_DATA_INITIALIZER;
	unsigned long timeout = DEFAULT_TIMEOUT;
	int opt_ind, opt_char, status;
	char *conv_temp;

	for (;;) {
		opt_char = getopt_long(argc, argv, optstr, longopts, &opt_ind);
		if (opt_char < 0)
			break;

		switch (opt_char) {
		case 'v':
			print_version();
		case 'h':
			print_help();
		case 't':
			timeout = strtoul(optarg, &conv_temp, 10);
			if (*conv_temp != '\0') {
				err_msg_and_die(argv[0],
						"invalid timeout value: %s\n",
						optarg);
			}
			break;
		case 'm':
			cb_data.max = strtoul(optarg, &conv_temp, 10);
			if (*conv_temp != '\0' || cb_data.max == 0) {
				err_msg_and_die(argv[0],
						"invalid limit: %s\n", optarg);
			}
			break;
		case 'd':
			cb_data.show_domain = 1;
			break;
		case 'r':
			cb_data.resolve = 1;
			break;
		case '?':
			return EXIT_FAILURE;
		default:
			abort();
		}
	}

	status = cast_discover(discovery_callback, &cb_data, timeout);
	if (status != CAST_OK) {
		err_msg_and_die(argv[0],
				"lscast: %s\n", cast_strerror(status));
	}

	return EXIT_SUCCESS;
}

