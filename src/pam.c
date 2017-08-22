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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <config.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <glib-object.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include <openssl/sha.h>

#include "pam_mount_template.h"


#define GRM_AUTH_LOG_ERR     (LOG_ERR | LOG_AUTHPRIV)

#define PAM_MOUNT_CONF_PATH             "/etc/security/pam_mount.conf.xml"
#define GOOROOM_MANAGEMENT_SERVER_CONF  "/etc/gooroom/gooroom-client-server-register/gcsr.conf"
#define GOOROOM_ONLINE_ACCOUNT          "gooroom-online-account"



struct MemoryStruct {
	char *memory;
	size_t size;
};



static char *
create_sha256_hash (const char *message)
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

static gboolean
is_online_account (const char *user)
{
	struct passwd *user_entry = getpwnam (user);
	if (!user_entry)
		return TRUE;

	gboolean ret = FALSE;

	char **tokens = g_strsplit (user_entry->pw_gecos, ",", -1);

	if (g_strv_length (tokens) > 4 ) {
		if (tokens[4] && (g_strcmp0 (tokens[4], GOOROOM_ONLINE_ACCOUNT) == 0)) {
			ret = TRUE;
		}
	}

	g_strfreev (tokens);

	return ret;
}

static char *
parse_url (const pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char     *url     = NULL;
	GError   *error   = NULL;
	GKeyFile *keyfile = NULL;

	keyfile = g_key_file_new ();

	g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "domain")) {
			url = g_key_file_get_string (keyfile, "domain", "glm", NULL);
		}
	}

	g_key_file_free (keyfile);
	g_clear_error (&error);

	return url;
}

static size_t
write_memory_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size *nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc (mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory */
		return 0;
	}

	memcpy (&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static void
change_mode_and_owner (const char *user, const char *file)
{
	if (!file)
		return;

	struct passwd *user_entry = getpwnam (user);

	if (chown (file, user_entry->pw_uid, user_entry->pw_gid) == -1) {
		return;
	}

	if (chmod (file, 0600) == -1) {
		return;
	}
}

static gboolean
is_mount_possible (const char *url)
{
	CURL *curl;
	CURLcode res = CURLE_OK;

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		curl_easy_setopt (curl, CURLOPT_URL, url);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 3); /* 3 sec */

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		return FALSE;
	}

	return TRUE;
}

static void
make_mount_xml (json_object *root_obj)
{
	char *volume_def_data = NULL;

	if (!root_obj) {
		goto done;
	}

	json_object *mounts_obj = NULL;
	json_object_object_get_ex (root_obj, "mounts", &mounts_obj);
	if (!mounts_obj) {
		goto done;
	}

	int i = 0, len = 0;;
	len = json_object_array_length (mounts_obj);

	for (i = 0; i < len; i++) {
		json_object *mount_obj = json_object_array_get_idx (mounts_obj, i);

		if (mount_obj) {
			json_object *protocol_obj = NULL, *url_obj = NULL, *mountpoint_obj = NULL;

			json_object_object_get_ex (mount_obj, "protocol", &protocol_obj);
			json_object_object_get_ex (mount_obj, "url", &url_obj);
			json_object_object_get_ex (mount_obj, "mountpoint", &mountpoint_obj);

			if (protocol_obj && url_obj && mountpoint_obj) {
				const char *protocol = json_object_get_string (protocol_obj);
				if (g_strcmp0 (protocol, "webdav") == 0) {
					const char *url = json_object_get_string (url_obj);
					const char *mountpoint = json_object_get_string (mountpoint_obj);
					if (is_mount_possible (url)) {
						volume_def_data = g_strdup_printf (pam_mount_volume_definitions, url, mountpoint);
					}
				}

				json_object_put (protocol_obj);
				json_object_put (url_obj);
				json_object_put (mountpoint_obj);
			}

			json_object_put (mount_obj);
		}

	}

	json_object_put (mounts_obj);

done:
	if (!volume_def_data)
		volume_def_data = g_strdup ("");

	if (g_file_test (PAM_MOUNT_CONF_PATH, G_FILE_TEST_EXISTS)) {
		GString *pam_mount_xml = g_string_new (NULL);
		g_string_append (pam_mount_xml, pam_mount_xml_template_prefix);
		g_string_append (pam_mount_xml, volume_def_data);
		g_string_append (pam_mount_xml, pam_mount_xml_template_suffix);

		char *str = g_strdup (pam_mount_xml->str);
		g_file_set_contents (PAM_MOUNT_CONF_PATH, str, -1, NULL);
		g_free (str);
		g_string_free (pam_mount_xml, TRUE);
	}

	g_free (volume_def_data);
}

static char *
get_real_name (char *data)
{
	char *ret = NULL;
	json_object *root_obj;
	enum json_tokener_error jerr = json_tokener_success;

	root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr == json_tokener_success) {
		json_object *ret_data_obj = NULL;
		json_object_object_get_ex (root_obj, "data", &ret_data_obj);
		if (ret_data_obj) {
			json_object *login_info_obj = NULL;
			json_object_object_get_ex (ret_data_obj, "loginInfo", &login_info_obj);
			if (login_info_obj) {
				json_object *user_name_obj = NULL;
				json_object_object_get_ex (login_info_obj, "user_name", &user_name_obj);
				if (user_name_obj) {
					ret = g_strdup (json_object_get_string (user_name_obj));
					json_object_put (user_name_obj);
				}
				json_object_put (login_info_obj);
			}
			json_object_put (ret_data_obj);
		}
	}

	if (root_obj)
		json_object_put (root_obj);

	return ret;
}

static gboolean
is_result_ok (char *data)
{
	gboolean ret = FALSE;
	json_object *obj;
	enum json_tokener_error jerr = json_tokener_success;

	obj = json_tokener_parse_verbose (data, &jerr);
	if (obj) {
		json_object *status_obj = NULL;
		json_object_object_get_ex (obj, "status", &status_obj);
		if (status_obj) {
			json_object *result_obj = NULL;
			json_object_object_get_ex (status_obj, "result", &result_obj);
			if (result_obj) {
				const char *result = json_object_get_string (result_obj);
				if (g_strcmp0 (result, "SUCCESS") == 0) {
					ret = TRUE;
				} else {
					ret = FALSE;
				}

				json_object_put (result_obj);
			}
			json_object_put (status_obj);
		}
		json_object_put (obj);
	}

	return ret;
}

static void
cleanup_data (pam_handle_t *pamh, void *data, int pam_end_status)
{
	free (data);
}

static gboolean
is_user_exists (const char *username)
{
	guint i = 0;
	gboolean ret = FALSE;
	char *contents = NULL;

	if (!username)
		return FALSE;

	g_file_get_contents ("/etc/passwd", &contents, NULL, NULL);
	if (!contents)
		return FALSE;

	char **lines = g_strsplit (contents, "\n", -1);
	for (i = 0; lines[i] != NULL; i++) {
		char **tokens = g_strsplit (lines[i], ":", -1);
		if (g_strcmp0 (tokens[0], username) == 0) {
			g_strfreev (tokens);
			ret = TRUE;
			break;
		}
		g_strfreev (tokens);
	}
	g_strfreev (lines);

	return ret;
}

static gboolean
add_account (const char *username, const char *realname)
{
	if (is_user_exists (username))
		return TRUE;

	char *cmd = NULL;

	if (realname) {
		cmd = g_strdup_printf ("/usr/sbin/adduser --shell /bin/bash --disabled-login --encrypt-home --gecos \"%s,,,,%s\" %s", realname, GOOROOM_ONLINE_ACCOUNT, username);
	} else {
		cmd = g_strdup_printf ("/usr/sbin/adduser --shell /bin/bash --disabled-login --encrypt-home --gecos \"%s,,,,%s\" %s", username, GOOROOM_ONLINE_ACCOUNT, username);
	}

	g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL);

	if (is_user_exists (username))
		return TRUE;

	return FALSE;
}

static int
login_from_online (pam_handle_t *pamh, const char *host, const char *user, const char *password)
{
	CURL *curl;
	CURLcode res = CURLE_OK;
	char *data = NULL;
	int retval = PAM_IGNORE;
	struct MemoryStruct chunk;

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *sha256pw = create_sha256_hash (password);
		char *user_sha256pw = g_strdup_printf ("%s%s", user, sha256pw);
		char *sha256_user_sha256pw= create_sha256_hash (user_sha256pw);

		char *url = g_strdup_printf ("https://%s/glm/v1/pam/auth", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, sha256_user_sha256pw);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, "/etc/ssl/certs/gooroom_client.crt");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, "/etc/ssl/private/gooroom_client.key");

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 3); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (sha256pw);
		g_free (user_sha256pw);
		g_free (sha256_user_sha256pw);

		g_free (url);
		g_free (post_fields);
	}

	curl_global_cleanup ();
	if (res != CURLE_OK) {
		retval = PAM_AUTH_ERR;
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Failed to request authentication.");
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	FILE *fp = fopen ("/tmp/debug.txt", "a+");
	fprintf (fp, "==============================================\n");
	fprintf (fp, "%s\n", data);
	fprintf (fp, "==============================================\n");
	fclose (fp);

	if (is_result_ok (data)) {
		char *real = get_real_name (data);
		if (add_account (user, real)) {
			/* store data for future reference */
			pam_set_data (pamh, "user_data", g_strdup (chunk.memory), cleanup_data);

			/* for pam_mount.so */
			json_object *root_obj;
			enum json_tokener_error jerr = json_tokener_success;

			root_obj = json_tokener_parse_verbose (data, &jerr);
			if (jerr == json_tokener_success) {
				json_object *ret_data_obj = NULL;
				json_object_object_get_ex (root_obj, "data", &ret_data_obj);
				if (ret_data_obj) {
					json_object *dt_info_obj = NULL;
					json_object_object_get_ex (ret_data_obj, "desktopInfo", &dt_info_obj);

					if (dt_info_obj) {
						make_mount_xml (dt_info_obj);
						json_object_put (dt_info_obj);
					}

					json_object_put (ret_data_obj);
				}
			}

			if (root_obj)
				json_object_put (root_obj);

			retval = PAM_SUCCESS;
		} else {
			syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Failed to create account.");
			retval = PAM_AUTH_ERR;
		}
	} else {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Authentication is failed.");
		retval = PAM_AUTH_ERR;
	}

	g_free (data);

done:
	g_free (chunk.memory);

	return retval;
}

static int
logout_from_online (const char *host, const char *token)
{
	CURL *curl;
	int retval = PAM_IGNORE;
	struct MemoryStruct chunk;

	if (!token || !host)
		return PAM_IGNORE;

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/logout", host);
		char *post_fields = g_strdup_printf ("login_token=%s", token);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, "/etc/ssl/certs/gooroom_client.crt");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, "/etc/ssl/private/gooroom_client.key");

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 3); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
	}

	curl_global_cleanup ();

	char *data = g_strdup (chunk.memory);
	if (data) {
		retval = (is_result_ok (data)) ? PAM_SUCCESS : PAM_IGNORE;
		g_free (data);
	}

	g_free (chunk.memory);

	return retval;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	char *url = NULL;
    const char *user, *password;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Couldn't get user name");
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth : Not an online account");
		return PAM_IGNORE;
	}

    url = parse_url (pamh, flags, argc, argv);
    if (!url) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Couldn't get URL");
		return PAM_IGNORE;
    }

	if (pam_get_item (pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS) {
		return PAM_SERVICE_ERR;
	}

	retval = login_from_online (pamh, url, user, password);

	g_free (url);

	return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#if 0
PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc, const char *argv[])
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}
#endif

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Couldn't get user name");
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth : Not an online account");
		return PAM_IGNORE;
	}

	/* Get the stored authtok here */
	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	if (!data) {
		return PAM_IGNORE;
	}

	char *file = g_strdup_printf ("/home/%s/.grm-user", user);
	g_file_set_contents (file, data, -1, NULL);
	change_mode_and_owner (user, file);
	g_free (file);

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	char *url = NULL;
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Couldn't get user name");
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth : Not an online account");
		return PAM_IGNORE;
	}

	url = parse_url (pamh, flags, argc, argv);
	if (!url) {
		syslog (GRM_AUTH_LOG_ERR, "pam_grm_auth: Couldn't get URL");
		return PAM_IGNORE;
	}

	/* Get the stored authtok here */
	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	retval = PAM_IGNORE;

	if (data) {
		json_object *root_obj;
		enum json_tokener_error jerr = json_tokener_success;

		root_obj = json_tokener_parse_verbose (data, &jerr);
		if (jerr == json_tokener_success) {
			json_object *ret_data_obj = NULL;
			json_object_object_get_ex (root_obj, "data", &ret_data_obj);
			if (ret_data_obj) {
				json_object *login_info_obj = NULL;
				json_object_object_get_ex (ret_data_obj, "loginInfo", &login_info_obj);
				if (login_info_obj) {
					json_object *login_token_obj = NULL;
					json_object_object_get_ex (login_info_obj, "login_token", &login_token_obj);
					if (login_token_obj) {
						retval = logout_from_online (url, json_object_get_string (login_token_obj));
						json_object_put (login_token_obj);
					}
					json_object_put (login_info_obj);
				}
				json_object_put (ret_data_obj);
			}
			json_object_put (root_obj);
		}
	}

	g_free (url);

	return retval;
}
