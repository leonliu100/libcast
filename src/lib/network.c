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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>

int cast_resolve(const char *hostname, uint32_t *ip_addr)
{
	struct sockaddr_in *saddr;
	struct addrinfo *result;
	int status;

	status = getaddrinfo(hostname, NULL, NULL, &result);
	if (status) {
		cast_err("resolver error: %s",
			 status == EAI_SYSTEM ? strerror(errno)
					      : gai_strerror(status));
		return -CAST_ERESOLVER;
	}

	saddr = (struct sockaddr_in *)result->ai_addr;
	*ip_addr = saddr->sin_addr.s_addr;
	freeaddrinfo(result);

	return 0;
}
