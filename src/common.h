/*
 * Copyright (C) 2015-2017 Gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>

#include <glib.h>

#define _(string) gettext(string)

#define GRM_USER                        ".grm-user"
#define GOOROOM_ACCOUNT                 "gooroom-account"
#define GOOGLE_ACCOUNT                  "google-account"
#define NAVER_ACCOUNT                   "naver-account"
#define GOOROOM_CERT                    "/etc/ssl/certs/gooroom_client.crt"
#define GOOROOM_PRIVATE_KEY             "/etc/ssl/private/gooroom_client.key"
#define GOOROOM_MANAGEMENT_SERVER_CONF  "/etc/gooroom/gooroom-client-server-register/gcsr.conf"

G_BEGIN_DECLS

#if 0
char *create_hash_for_type1     (const char *user, const char *password, gpointer user_data);
char *create_hash_for_type2     (const char *user, const char *password, gpointer user_data);
char *create_hash_for_default   (const char *user, const char *password, gpointer user_data);

#define HASH_FUNC(name, hash_func) {name, hash_func}

static struct {
	const char *name;
	char *(*hash_func)(const char *, const char *, gpointer);
} hash_funcs [] = {
	HASH_FUNC("type1", create_hash_for_type1),
	HASH_FUNC("type2", create_hash_for_type2),
	HASH_FUNC("default", create_hash_for_default)
};
#endif

char *md5_hash    (const char *message);
char *sha256_hash (const char *message);

char *create_hash (const char *user, const char *password, gpointer data);

char *parse_url   (void);

G_END_DECLS

#endif
