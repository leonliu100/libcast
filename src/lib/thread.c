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

void cast_mutex_init(struct cast_mutex *mutex)
{
	pthread_mutex_init(&mutex->mutex, NULL);
}

void cast_mutex_free(struct cast_mutex *mutex)
{
	pthread_mutex_destroy(&mutex->mutex);
}

void cast_mutex_lock(struct cast_mutex *mutex)
{
	pthread_mutex_lock(&mutex->mutex);
}

void cast_mutex_unlock(struct cast_mutex *mutex)
{
	pthread_mutex_unlock(&mutex->mutex);
}
