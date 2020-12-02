/*
 * Copyright (C) 2015-2019 Gooroom <gooroom@gooroom.kr>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <glib.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#include "common.h"

#define HASH_FUNC(name, hash_func) {name, hash_func}

static char *create_hash_for_md5    (const char *user, const char *password, gpointer user_data);
static char *create_hash_for_text   (const char *user, const char *password, gpointer user_data);
static char *create_hash_for_sha256 (const char *user, const char *password, gpointer user_data);

static struct {
	const char *name;
	char *(*hash_func)(const char *, const char *, gpointer);
} hash_funcs [] = {
	HASH_FUNC("md5", create_hash_for_md5),
	HASH_FUNC("text", create_hash_for_text),
	HASH_FUNC("sha256", create_hash_for_sha256)
};

char *
md5_hash (const char *message)
{
	unsigned char digest[MD5_DIGEST_LENGTH];

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, message, strlen (message));
	MD5_Final(digest, &ctx);

	char *str_hash = g_new0 (char, MD5_DIGEST_LENGTH*2+1);
	memset (str_hash, 0x00, MD5_DIGEST_LENGTH*2+1);

	for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf (&str_hash[i*2], "%02x", (unsigned int)digest[i]);

	return str_hash;
}

char *
sha256_hash (const char *message)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, message, strlen (message));
	SHA256_Final(digest, &ctx);

	char *str_hash = g_new0 (char, SHA256_DIGEST_LENGTH*2+1);
	memset (str_hash, 0x00, SHA256_DIGEST_LENGTH*2+1);

	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf (&str_hash[i*2], "%02x", (unsigned int)digest[i]);

	return str_hash;
}

static char *
create_hash_for_md5 (const char *user, const char *password, gpointer user_data)
{
	return md5_hash (password);
}

static char *
create_hash_for_text (const char *user, const char *password, gpointer user_data)
{
	return g_uri_escape_string (password, NULL, TRUE);
}

static char *
create_hash_for_sha256 (const char *user, const char *password, gpointer data)
{
	char *str_hash = NULL;
	char *sha256pw = NULL;
	char *user_sha256pw = NULL;

	sha256pw = sha256_hash (password);
	user_sha256pw = g_strdup_printf ("%s%s", user, sha256pw);

	str_hash = sha256_hash (user_sha256pw);

	free (sha256pw);
	free (user_sha256pw);

	return str_hash;
}

char *
create_hash (const char *user, const char *password, gpointer data)
{
	GError   *error    = NULL;
	GKeyFile *keyfile  = NULL;
	char *str_hash = NULL;
	char *pw_system_type = NULL;

	keyfile = g_key_file_new ();

	g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "certificate")) {
			pw_system_type = g_key_file_get_string (keyfile, "certificate", "password_system_type", NULL);
		}
	}

	if (!pw_system_type)
		pw_system_type = g_strdup ("sha256");

	guint i;
	for (i = 0; i < G_N_ELEMENTS (hash_funcs); i++) {
		char *(*hash_func) (const char *, const char *, gpointer);
		hash_func = hash_funcs[i].hash_func;

		if (g_str_equal (pw_system_type, hash_funcs[i].name)) {
			str_hash = hash_func (user, password, data);
			break;
		}
	}

	if (!str_hash)
		str_hash = create_hash_for_sha256 (user, password, data);

	g_free (pw_system_type);
	g_key_file_free (keyfile);
	g_clear_error (&error);

	return str_hash;
}

char *
parse_url (void)
{
	int try = 1;
	char  *url = NULL;
	GError  *error = NULL;
	GKeyFile *keyfile = NULL;

	while (!g_file_test (GOOROOM_MANAGEMENT_SERVER_CONF, G_FILE_TEST_EXISTS)) {
		g_usleep (G_USEC_PER_SEC / 10); // waiting for 1/10 sec
		if (try > 1200) {
			syslog (LOG_ERR, "pam_gooroom : No such file or directory [%s]", GOOROOM_MANAGEMENT_SERVER_CONF);
			return NULL;
		}
		try++;
	}

	keyfile = g_key_file_new ();

	g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF,
                               G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "domain"))
			url = g_key_file_get_string (keyfile, "domain", "glm", NULL);
	}

	g_key_file_free (keyfile);

	g_clear_error (&error);

	return url;
}
