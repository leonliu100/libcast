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

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/error.h>

static const char *const service_type = "_googlecast._tcp";

struct discovery_context {
	AvahiSimplePoll *simple_poll;
	AvahiClient *client;
	int errnum;
	cast_discover_callback user_callback;
	void *user_private;
};
#define DISCOVERY_CTX_INIT { NULL, NULL, 0, NULL, NULL }

static void browse_callback(AvahiServiceBrowser *browser CAST_UNUSED,
			    AvahiIfIndex interface CAST_UNUSED,
			    AvahiProtocol protocol CAST_UNUSED,
			    AvahiBrowserEvent event, const char *name,
			    const char *type CAST_UNUSED, const char *domain,
			    AvahiLookupResultFlags flags CAST_UNUSED,
			    void* userdata)
{
	struct discovery_context *ctx = userdata;
	int status;

	switch (event) {
	case AVAHI_BROWSER_FAILURE:
		cast_err("avahi browser error: %s",
			 avahi_strerror(avahi_client_errno(ctx->client)));
		avahi_simple_poll_quit(ctx->simple_poll);
		ctx->errnum = -CAST_EDISCOVERY;
		break;
	case AVAHI_BROWSER_NEW:
		cast_dbg("avahi: new service %s of type %s in domain %s",
			 name, type, domain);
		status = ctx->user_callback(name, domain, ctx->user_private);
		if (status == CAST_DISCOVER_STOP)
			avahi_simple_poll_quit(ctx->simple_poll);
		break;
	default:
		break;
	}
}

static void client_callback(AvahiClient *client,
			    AvahiClientState state, void *userdata)
{
	struct discovery_context *ctx = userdata;

	if (state == AVAHI_CLIENT_FAILURE) {
		cast_err("avahi client error: %s",
			 avahi_strerror(avahi_client_errno(client)));
		avahi_simple_poll_quit(ctx->simple_poll);
		ctx->errnum = -CAST_EDISCOVERY;
	}
}

int cast_discover(cast_discover_callback cb, void *priv, unsigned long timeout)
{
	struct discovery_context ctx = DISCOVERY_CTX_INIT;
	struct timeval tv_start, tv_stop, tv_diff;
	int status, ret = CAST_OK, cli_errno;
	unsigned int elapsed_time = 0;
	AvahiServiceBrowser *browser;
	const AvahiPoll *poll;

	if (!cb)
		return -CAST_EINVAL;

	ctx.user_callback = cb;
	ctx.user_private = priv;

	ctx.simple_poll = avahi_simple_poll_new();
	if (!ctx.simple_poll) {
		cast_err("failed to create avahi simple_poll object");
		ret = -CAST_ENOMEM;
		goto out;
	}

	poll = avahi_simple_poll_get(ctx.simple_poll);
	ctx.client = avahi_client_new(poll, 0, client_callback,
				      &ctx, &status);
	if (!ctx.client) {
		cast_err("failed to create avahi client object: %s",
			 avahi_strerror(status));
		ret = status = AVAHI_ERR_NO_MEMORY ? -CAST_ENOMEM
						   : -CAST_EDISCOVERY;
		goto out_free_poll;
	}

	browser = avahi_service_browser_new(ctx.client, AVAHI_IF_UNSPEC,
					    AVAHI_PROTO_UNSPEC, service_type,
					    NULL, 0, browse_callback, &ctx);
	if (!browser) {
		cli_errno = avahi_client_errno(ctx.client);
		cast_err("failed to create avahi service browser: %s",
			 avahi_strerror(cli_errno));
		ret = cli_errno = AVAHI_ERR_NO_MEMORY ? -CAST_ENOMEM
						      : -CAST_EDISCOVERY;
		goto out_free_client;
	}

	do {
		gettimeofday(&tv_start, NULL);
		status = avahi_simple_poll_iterate(ctx.simple_poll, timeout);
		gettimeofday(&tv_stop, NULL);
		if (status < 0) {
			cast_err("avahi poll error: %s",
				 avahi_strerror(status));
			ret = -CAST_EDISCOVERY;
			goto out_free_browser;
		} else if (status == 1) {
			cast_dbg("avahi poll quit requested");
			break;
		}

		timersub(&tv_stop, &tv_start, &tv_diff);
		elapsed_time += cast_timeval_to_msec(&tv_diff);
		timeout -= elapsed_time > timeout ? timeout : elapsed_time;
	} while (elapsed_time < timeout);

out_free_browser:
	avahi_service_browser_free(browser);

out_free_client:
	avahi_client_free(ctx.client);

out_free_poll:
	avahi_simple_poll_free(ctx.simple_poll);

out:
	return ret;
}
