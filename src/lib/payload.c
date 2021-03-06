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

struct payload_type {
	const char *str;
	int val;
};

static const struct payload_type payload_types[] = {
	{
		.str = "CLOSE",
		.val = CAST_PAYLOAD_CLOSE,
	},
	{
		.str = "PING",
		.val = CAST_PAYLOAD_PING,
	},
	{
		.str = "PONG",
		.val = CAST_PAYLOAD_PONG,
	}
};

static int payload_type_from_str(const char *type)
{
	unsigned int i;

	for (i = 0; i < CAST_ARRAY_SIZE(payload_types); i++) {
		if (strcmp(payload_types[i].str, type) == 0)
			return payload_types[i].val;
	}

	return CAST_PAYLOAD_UNKNOWN;
}

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

static struct cast_payload * make_simple_type_payload(const char *type)
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

struct cast_payload * cast_payload_get_status_new(int request_id)
{
	struct cast_payload *payload;
	json_object *field_obj;

	payload = alloc_payload();
	if (!payload)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	field_obj = json_object_new_int(request_id);
	if (!field_obj) {
		json_object_put(payload->obj);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	json_object_object_add(payload->obj, "requestId", field_obj);

	field_obj = json_object_new_string("GET_STATUS");
	if (!field_obj) {
		json_object_put(payload->obj);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	json_object_object_add(payload->obj, "type", field_obj);

	return payload;
}

void cast_payload_free(struct cast_payload *payload)
{
	json_object_put(payload->obj);
	free(payload);
}

int cast_payload_type_get(struct cast_payload *payload)
{
	json_object *type_obj;
	const char *type_str;
	json_bool status;
	int type;

	type = json_object_get_type(payload->obj);
	if (type != json_type_object) {
		type = -CAST_EINVAL;
		goto out;
	}

	status = json_object_object_get_ex(payload->obj, "type", &type_obj);
	if (!status) {
		type = -CAST_EINVAL;
		goto out;
	}

	type = json_object_get_type(type_obj);
	if (type != json_type_string) {
		type = -CAST_EINVAL;
		goto out;
	}

	type_str = json_object_get_string(type_obj);
	type = payload_type_from_str(type_str);

out:
	return type;
}

char * cast_payload_to_string(struct cast_payload *payload)
{
	return (char *)json_object_to_json_string(payload->obj);
}

struct cast_payload * cast_payload_from_string(const char *str)
{
	struct cast_payload *payload;

	payload = malloc(sizeof(*payload));
	if (!payload)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	payload->obj = json_tokener_parse(str);
	if (!payload->obj) {
		cast_err("error parsing JSON: %s", str);
		return CAST_ERR_PTR(-CAST_EINVAL);
	}

	return payload;
}
