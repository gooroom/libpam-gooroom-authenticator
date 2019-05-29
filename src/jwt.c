/* Copyright (C) 2015-2018 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#include "jwt.h"

#include <stdlib.h>
#include <string.h>

#include <b64/cencode.h>
#include <b64/cdecode.h>


int
jwt_Base64decode (char *plain_dst, const char *coded_src)
{
	base64_decodestate _state;
	int _count = 0;

	base64_init_decodestate(&_state);
	_count = base64_decode_block(coded_src, strlen(coded_src), plain_dst, &_state);

	return _count;
}

void
*jwt_b64_decode(const char *src, int *ret_len)
{
	void *buf;
	char *new;
	int len, i, z;

	/* Decode based on RFC-4648 URI safe encoding. */
	len = strlen(src);
	new = alloca(len + 4);
	if (!new)
		return NULL;

	for (i = 0; i < len; i++) {
		switch (src[i]) {
			case '-':
				new[i] = '+';
				break;
			case '_':
				new[i] = '/';
				break;
			default:
				new[i] = src[i];
		}
	}
	z = 4 - (i % 4);
	if (z < 4) {
		while (z--)
			new[i++] = '=';
	}
	new[i] = '\0';

	buf = malloc(i);
	if (buf == NULL)
		return NULL;

	*ret_len = jwt_Base64decode(buf, new);

	return buf;
}
