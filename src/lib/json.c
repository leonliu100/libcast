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

char * make_simple_type_payload(const char *type)
{
	json_object *obj, *strobj;
	char *str;

	obj = json_object_new_object();
	if (!obj)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	strobj = json_object_new_string(type);
	if (!strobj) {
		json_object_put(obj);
		return CAST_ERR_PTR(-CAST_ENOMEM);
	}

	json_object_object_add(obj, "type", strobj);

	str = strdup(json_object_to_json_string(obj));
	json_object_put(obj);
	if (!str)
		return CAST_ERR_PTR(-CAST_ENOMEM);

	return str;
}

char * cast_json_make_connect_payload(void)
{
	return make_simple_type_payload("CONNECT");
}

char * cast_json_make_ping_payload(void)
{
	return make_simple_type_payload("PING");
}
