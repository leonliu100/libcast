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

#include <string.h>
#include <json-c/json.h>

struct cast_payload {
	json_object *obj;
};

static struct cast_payload * alloc_payload(void)
{
	struct cast_payload *payload;

	payload = malloc(sizeof(*payload));
	if (!payload)
		return NULL;

	payload->obj = json_object_new_object();
	if (!payload->obj) {
		free(payload);
		return NULL;
	}

	return payload;
}

struct cast_payload * make_simple_type_payload(const char *type)
{
	struct cast_payload *payload;
	json_object *strobj;

	payload = alloc_payload();
	if (!payload)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	strobj = json_object_new_string(type);
	if (!strobj) {
		json_object_put(payload->obj);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	json_object_object_add(payload->obj, "type", strobj);

	return payload;
}

struct cast_payload * cast_payload_connect_new(void)
{
	return make_simple_type_payload("CONNECT");
}

struct cast_payload * cast_payload_close_new(void)
{
	return make_simple_type_payload("CLOSE");
}

struct cast_payload * cast_payload_ping_new(void)
{
	return make_simple_type_payload("PING");
}

struct cast_payload * cast_payload_pong_new(void)
{
	return make_simple_type_payload("PONG");
}

void cast_payload_free(struct cast_payload *payload)
{
	json_object_put(payload->obj);
	free(payload);
}

int cast_payload_type_get(struct cast_payload *payload CAST_UNUSED)
{
	return -1;
}

char * cast_payload_to_string(struct cast_payload *payload)
{
	return (char *)json_object_to_json_string(payload->obj);
}

struct cast_payload * cast_payload_from_string(const char *str)
{
	struct cast_payload *payload;

	payload = alloc_payload();
	if (!payload)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	payload->obj = json_tokener_parse(str);
	if (!payload->obj) {
		cast_err("error parsing JSON: %s", str);
		return CAST_ERR_PTR(-CAST_EINVAL);
	}

	return payload;
}
