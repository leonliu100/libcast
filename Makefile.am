AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
LIBS =

AM_CPPFLAGS = -I$(top_srcdir)/include -include $(top_srcdir)/config.h -Wextra
AM_CPPFLAGS += -fvisibility=hidden

lib_LTLIBRARIES = libcast.la

libcast_la_SOURCES = \
	src/lib/discovery.c \
	src/lib/error.c \
	src/lib/logging.c \
	src/lib/util.c \
	src/lib/version.c \
	src/lib/connection.c \
	src/lib/ssl.c \
	src/lib/payload.c \
	src/lib/message.pb-c.c

CLEANFILES = src/lib/message.pb-c.c src/lib/message.pb-c.h
CLEANFILES += src/tools/castdctl.pb-c.c src/tools/castdctl.pb-c.h

libcast_la_LDFLAGS = --version-number $(LIB_VER_MAJOR):$(LIB_VER_MINOR):$(LIB_VER_RELEASE)
libcast_la_LDFLAGS += -version-info 1:0:0
libcast_la_LDFLAGS += -lavahi-common -lavahi-client -ljson-c -lssl -lprotobuf-c

protofiles:
	protoc-c $(top_srcdir)/src/lib/message.proto --c_out=./
	protoc-c $(top_srcdir)/src/tools/castdctl.proto --c_out=./
.PHONY: protofiles

all: protofiles

bin_PROGRAMS = castctl castd lscast

castctl_SOURCES = src/tools/castctl.c src/tools/castdctl.pb-c.c
castctl_LDFLAGS = -lprotobuf-c

castd_SOURCES = src/tools/castd.c src/tools/castdctl.pb-c.c
castd_LDFLAGS = -lcast -lprotobuf-c

lscast_SOURCES = src/tools/lscast.c
lscast_LDFLAGS = -lcast

library_includedir = include
library_include_HEADERS = include/libcast.h
