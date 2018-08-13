/*
 * Copyright (c) 2015 - 2017 gooroom <gooroom@gooroom.kr>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <glib.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#define HASH_FUNC(name, hash_func) {name, hash_func}

char *create_hash_for_type1     (const char *user, const char *password, gpointer user_data);
char *create_hash_for_type2     (const char *user, const char *password, gpointer user_data);
char *create_hash_for_default (const char *user, const char *password, gpointer user_data);

static struct {
	const char *name;
	char *(*hash_func)(const char *, const char *, gpointer);
} hash_funcs [] = {
	HASH_FUNC("type1", create_hash_for_type1),
	HASH_FUNC("type2", create_hash_for_type2),
	HASH_FUNC("default", create_hash_for_default)
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

char *
create_hash_for_type1 (const char *user, const char *password, gpointer user_data)
{
	return md5_hash (password);
}

char *
create_hash_for_type2 (const char *user, const char *password, gpointer user_data)
{
	return g_uri_escape_string (password, NULL, TRUE);
}

char *
create_hash_for_default (const char *user, const char *password, gpointer data)
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
