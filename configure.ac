#
# Copyright (C) 2016 Bartosz Golaszewski <bartekgola@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

AC_PREREQ(2.61)

AC_INIT([libcast], 0.0.1)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([autostuff])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_SUBST(LIB_VER_MAJOR, 0)
AC_SUBST(LIB_VER_MINOR, 0)
AC_SUBST(LIB_VER_RELEASE, 1)

AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADER([config.h])

AC_ARG_ENABLE([debug],
	[AC_HELP_STRING([--enable-debug],
		[enable verbose debug messages from the library [default=no]])],
	[
		if test "x$enableval" = xno;
		then
			with_debug=false
		else
			AC_DEFINE([ENABLE_DEBUG], [1], [Enable debug output])
			with_debug=true
		fi
	],
	[with_debug=false])
AM_CONDITIONAL([WITH_DEBUG], [test x$with_debug = xtrue])

AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_HEADER_STDC

AC_CHECK_FUNC([getenv], [], [AC_MSG_ERROR([getenv() unavailable])])
AC_CHECK_FUNC([getaddrinfo], [], [AC_MSG_ERROR([getaddrinfo() unavailable])])
AC_CHECK_FUNC([poll], [], [AC_MSG_ERROR([poll() unavailable])])
AC_CHECK_FUNC([strdup], [], [AC_MSG_ERROR([strdup() unavailable])])

AC_FUNC_MALLOC

AC_CHECK_LIB([avahi-common], [avahi_simple_poll_new], [],
		[AC_MSG_ERROR([libavahi-common not found])])
AC_CHECK_LIB([avahi-client], [avahi_client_new], [],
		[AC_MSG_ERROR([libavahi-client not found])])
AC_CHECK_LIB([protobuf-c], [protobuf_c_message_pack], [],
		[AC_MSG_ERROR([libprotobuf-c not found])])
AC_CHECK_LIB([pthread], [pthread_mutex_lock], [],
		[AC_MSG_ERROR([libpthread not found])])
AC_CHECK_LIB([ssl], [ERR_load_SSL_strings], [],
		[AC_MSG_ERROR([libssl (openssl) not found])])
AC_CHECK_LIB([json-c], [json_object_new_object], [],
		[AC_MSG_ERROR([libjson-c not found])])

AC_CHECK_HEADERS([getopt.h], [], [AC_MSG_ERROR([getopt.h header not found])])
AC_CHECK_HEADERS([limits.h], [], [AC_MSG_ERROR([limits.h header not found])])
AC_CHECK_HEADERS([stdint.h], [], [AC_MSG_ERROR([stdint.h header not found])])
AC_CHECK_HEADERS([pthread.h], [], [AC_MSG_ERROR([pthread header not found])])
AC_CHECK_HEADERS([openssl/ssl.h openssl/bio.h], [],
		[AC_MSG_ERROR([openssl headers not found])])
AC_CHECK_HEADERS([protobuf-c/protobuf-c.h], [],
		[AC_MSG_ERROR([protobuf-c.h header not found])])
AC_CHECK_HEADERS([avahi-client/client.h], [],
		[AC_MSG_ERROR([avahi-client/client.h header not found])])
AC_CHECK_HEADERS([avahi-common/simple-watch.h], [],
		[AC_MSG_ERROR([avahi-common/simple-watch.h header not found])])
AC_CHECK_HEADERS([json-c/json.h], [],
		[AC_MSG_ERROR([json-c/json.h header not found])])

AC_CHECK_PROG([has_protocc], [protoc-c], [yes], [no])
if test "x$has_protocc" = xno;
then
	AC_MSG_ERROR([protoc-c not found!])
fi

AC_HEADER_STDC

AC_CONFIG_FILES([Makefile])

CFLAGS="$CFLAGS -Wall"

AC_OUTPUT
