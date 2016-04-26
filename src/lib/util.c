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

#define MSEC_PER_SEC	1000
#define USEC_PER_MSEC	1000

unsigned int cast_timeval_to_msec(struct timeval *tv)
{
	return tv->tv_sec * MSEC_PER_SEC + tv->tv_usec / USEC_PER_MSEC;
}
