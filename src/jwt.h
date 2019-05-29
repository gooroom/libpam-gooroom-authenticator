/* Copyright (C) 2015-2017 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __JWT_H__
#define __JWT_H__

#include <stdio.h>

/* Helper routines. */
int jwt_Base64decode(char *plain_dst, const char *coded_src);

void *jwt_b64_decode(const char *src, int *ret_len);

#endif /* __JWT_H__ */
