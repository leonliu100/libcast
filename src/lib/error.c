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

static const char *const error_strings[] = {
	"no error",
	"out of memory",
	"invalid argument",
	"cast discovery error",
	"generic resolver error",
	"connection error",
	"ssl encryption error",
	"not enough bytes written",
	"not enough bytes read",
	"connection closed by remote peer"
};

const char * cast_strerror(int errnum)
{
	errnum = abs(errnum);

	if (errnum >= _CAST_MAX_ERR)
		return "undefined error number";

	return error_strings[errnum];
}
