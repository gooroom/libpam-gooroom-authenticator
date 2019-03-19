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
#include <sys/fsuid.h>
#include <grp.h>
#include <locale.h>
#include <shadow.h>

#include <ecryptfs.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include "common.h"
#include "cleanup.h"
#include "nfc_auth.h"
#include "pam_mount_template.h"
#include "custom-hash-helper.h"


#define GRM_USER                        ".grm-user"
#define GOOROOM_CERT                    "/etc/ssl/certs/gooroom_client.crt"
#define GOOROOM_PRIVATE_KEY             "/etc/ssl/private/gooroom_client.key"
#define PAM_MOUNT_CONF_PATH             "/etc/security/pam_mount.conf.xml"
#define GOOROOM_MANAGEMENT_SERVER_CONF  "/etc/gooroom/gooroom-client-server-register/gcsr.conf"

#define PAM_FORGET(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}

struct MemoryStruct {
	char *memory;
	size_t size;
};

static int CONNECTION_TIMEOUT = 30; // Default Timeout: 30sec



static RSA *
createRSA (unsigned char *key, int public)
{
	RSA *rsa = NULL;
	BIO *keybio = NULL;

	keybio = BIO_new_mem_buf (key, -1);
	if (!keybio) {
		return NULL;
	}

	if(public == 1) {
		rsa = PEM_read_bio_RSA_PUBKEY (keybio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSAPrivateKey (keybio, &rsa, NULL, NULL);
	}

	return rsa;
}

static int
encrypt_with_public_key (unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
	RSA *rsa = createRSA (key, 1);

	return RSA_public_encrypt (data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
}

static int
decrypt_with_private_key (unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
	RSA *rsa = createRSA (key, 0);

	return RSA_private_decrypt (data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
}

static gboolean
send_info_msg (pam_handle_t *pamh, const char *msg)
{
	const struct pam_message mymsg = {
		.msg_style = PAM_TEXT_INFO,
		.msg = msg,
	};
	const struct pam_message *msgp = &mymsg;
	const struct pam_conv *pc;
	struct pam_response *resp;
	int r;

	r = pam_get_item (pamh, PAM_CONV, (const void **) &pc);
	if (r != PAM_SUCCESS)
		return FALSE;

	if (!pc || !pc->conv)
		return FALSE;

	return (pc->conv (1, &msgp, &resp, pc->appdata_ptr) == PAM_SUCCESS);
}

json_object *
JSON_OBJECT_GET (json_object *root_obj, const char *key)
{
	if (!root_obj) return NULL;

	json_object *ret_obj = NULL;

	json_object_object_get_ex (root_obj, key, &ret_obj);

	return ret_obj;
}

char *
get_login_token (const char *data)
{
	g_return_val_if_fail (data != NULL, NULL);

	gchar *token = NULL;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr == json_tokener_success) {
		json_object *obj1 = NULL, *obj2 = NULL, *obj3= NULL;
		obj1 = JSON_OBJECT_GET (root_obj, "data");
		obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
		obj3 = JSON_OBJECT_GET (obj2, "login_token");
		if (obj3) {
			token = g_strdup (json_object_get_string (obj3));
		}
		json_object_put (root_obj);
	}

	return token;
}

static int
get_passphrase_from_online (const char *data, unsigned char *passphrase)
{
	if (!data) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
		return -1;
	}

	int ret = -1;
	char *base64_encoded_passphrase = NULL;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);

	if (jerr == json_tokener_success) {
		json_object *obj1 = NULL, *obj2 = NULL, *obj3= NULL;
		obj1 = JSON_OBJECT_GET (root_obj, "data");
		obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
		obj3 = JSON_OBJECT_GET (obj2, "passphrase");
		if (obj3) {
			base64_encoded_passphrase = g_uri_unescape_string (json_object_get_string (obj3), NULL);
		}
		json_object_put (root_obj);
	}

	if (!base64_encoded_passphrase || strlen (base64_encoded_passphrase) == 0) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get passphrase from user_data [%s]", __FUNCTION__);
		ret = 1;
	} else {
		char *private_key = NULL;
		g_file_get_contents (GOOROOM_PRIVATE_KEY, &private_key, NULL, NULL);
		if (private_key) {
			unsigned long outlen = 0;
			unsigned char *encrypted_passphrase = g_base64_decode (base64_encoded_passphrase, &outlen);
			if (encrypted_passphrase && outlen > 0) {
				int decrypted_length = decrypt_with_private_key (encrypted_passphrase, 256, (unsigned char *)private_key, passphrase);
				if (decrypted_length != -1) {
					ret = 0;
				} else {
					syslog (LOG_ERR, "pam_grm_auth: Error attempting to decrypt passphrase with private key [%s]", __FUNCTION__);
				}
			} else {
				syslog (LOG_ERR, "pam_grm_auth: Base64 decoding error [%s]", __FUNCTION__);
			}
			g_free (encrypted_passphrase);
		} else {
			syslog (LOG_ERR, "pam_grm_auth: Error attempting to get private key [%s]", __FUNCTION__);
		}
		g_free (private_key);
	}

	g_free (base64_encoded_passphrase);

	return ret;
}

static char *
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
		pw_system_type = g_strdup ("default");

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
		str_hash = create_hash_for_default (user, password, data);

	g_free (pw_system_type);
	g_key_file_free (keyfile);
	g_clear_error (&error);

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
		if (tokens[4] && (g_strcmp0 (tokens[4], GOOROOM_ACCOUNT) == 0)) {
			ret = TRUE;
		}
	}

	g_strfreev (tokens);

	return ret;
}

static void
delete_config_files (const char *user)
{
	struct passwd *user_entry = getpwnam (user);
	if (user_entry) {
		char *grm_user = g_strdup_printf ("/var/run/user/%d/gooroom/%s", user_entry->pw_uid, GRM_USER);

		/* delete /var/run/user/$(uid)/gooroom/.grm-user */
		g_remove (grm_user);
		g_free (grm_user);
	}
}

static void
make_sure_to_create_save_dir (const char *user)
{
	struct passwd *user_entry = getpwnam (user);
	if (user_entry) {
		char *gooroom_save_dir = g_strdup_printf ("/var/run/user/%d/gooroom", user_entry->pw_uid);

		if (!g_file_test (gooroom_save_dir, G_FILE_TEST_EXISTS)) {
			g_mkdir (gooroom_save_dir, 0700);

			if (chown (gooroom_save_dir, user_entry->pw_uid, user_entry->pw_gid) == -1) {
				syslog (LOG_ERR, "pam_grm_auth: Error chown [%s]", __FUNCTION__);
			}
		}
		g_free (gooroom_save_dir);
	}
}

static char *
parse_url (void)
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
	if (!file) return;

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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
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
	mounts_obj = JSON_OBJECT_GET (root_obj, "mounts");
	if (!mounts_obj) {
		goto done;
	}

	int i = 0, len = 0;;
	len = json_object_array_length (mounts_obj);

	for (i = 0; i < len; i++) {
		json_object *mount_obj = json_object_array_get_idx (mounts_obj, i);

		if (mount_obj) {
			json_object *protocol_obj = NULL, *url_obj = NULL, *mountpoint_obj = NULL;

			protocol_obj = JSON_OBJECT_GET (mount_obj, "protocol");
			url_obj = JSON_OBJECT_GET (mount_obj, "url");
			mountpoint_obj = JSON_OBJECT_GET (mount_obj, "mountpoint");

			if (protocol_obj && url_obj && mountpoint_obj) {
				const char *protocol = json_object_get_string (protocol_obj);
				if (protocol && g_strcmp0 (protocol, "webdav") == 0) {
					const char *url = json_object_get_string (url_obj);
					const char *mountpoint = json_object_get_string (mountpoint_obj);
					if (url && mountpoint && is_mount_possible (url)) {
						volume_def_data = g_strdup_printf (pam_mount_volume_definitions, url, mountpoint);
					}
				}
			}
		}
	}

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

static long
strtoday (const char *date /* yyyy-mm-dd */)
{
	int year = 0, month = 0, day = 0;

	if ((date != NULL) && (strlen (date) == 10) &&
		(sscanf (date, "%d-%d-%d", &year, &month, &day) != 0)) {

		if (year != 0 && month != 0 && day != 0) {
			GDateTime *dt = g_date_time_new_local (year, month, day, 0, 0, 0);
			long days = (long)(g_date_time_to_unix (dt) / (24 * 60 * 60));
			g_date_time_unref (dt);

			return days;
		}
	}

	return ((long)(time(NULL) / (60 * 60 * 24)));
}

static void
run_chage_l (const char *json_data, long *lastdays, int *maxdays)
{
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json_data, &jerr);

	*maxdays = 99999;
	*lastdays = (long)(time(NULL) / (60 * 60 * 24));

	if (jerr == json_tokener_success) {
		json_object *dt_obj, *login_obj, *login_obj1, *login_obj2, *login_obj3;
		dt_obj = JSON_OBJECT_GET (root_obj, "data");
		login_obj = JSON_OBJECT_GET (dt_obj, "loginInfo");
		login_obj1 = JSON_OBJECT_GET (login_obj, "pwd_last_day");
		login_obj2 = JSON_OBJECT_GET (login_obj, "pwd_max_day");
		login_obj3 = JSON_OBJECT_GET (login_obj, "pwd_temp_yn");
		if (login_obj3) {
			const char *value = json_object_get_string (login_obj3);
			if (value && g_strcmp0 (value, "Y") == 0) {
				*lastdays = -1;
				*maxdays = 99999;
				goto done;
			}
		}

		if (login_obj1 && login_obj2) {
			const char *value = json_object_get_string (login_obj1);
			*lastdays = strtoday (value);
			*maxdays = json_object_get_int (login_obj2);
			goto done;
		}
	}

done:
	json_object_put (root_obj);
}

static char *
get_real_name (char *json_data)
{
	char *ret = NULL;
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json_data, &jerr);
	if (jerr == json_tokener_success) {
		json_object *obj1 = NULL, *obj2 = NULL, *obj3 = NULL;
		obj1 = JSON_OBJECT_GET (root_obj, "data");
		obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
		obj3 = JSON_OBJECT_GET (obj2, "user_name");
		if (obj3) {
			ret = g_strdup (json_object_get_string (obj3));
		}
		json_object_put (root_obj);
	}

	return ret;
}

static gboolean
is_result_ok (char *json_data)
{
	gboolean ret = FALSE;
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json_data, &jerr);

	if (jerr == json_tokener_success) {
		json_object *obj1 = NULL, *obj2 = NULL;
		obj1 = JSON_OBJECT_GET (root_obj, "status");
		obj2 = JSON_OBJECT_GET (obj1, "result");
		if (obj2) {
			const char *result = json_object_get_string (obj2);
			ret = (g_strcmp0 (result, "SUCCESS") == 0) ? TRUE : FALSE;
		}
		json_object_put (root_obj);
	}

	return ret;
}

static void
cleanup_data (pam_handle_t *pamh, void *data, int pam_end_status)
{
	g_free (data);
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
	char *cmd = NULL;

	if (is_user_exists (username)) {
		cmd = g_strdup_printf ("/usr/bin/chfn -f %s %s", (realname ? realname : username), username);
	} else {
		const char *cmd_prefix = "/usr/sbin/adduser --force-badname --shell /bin/bash --disabled-login --encrypt-home --gecos";
		if (realname) {
			cmd = g_strdup_printf ("%s \"%s,,,,%s\" %s", cmd_prefix, realname, GOOROOM_ACCOUNT, username);
		} else {
			cmd = g_strdup_printf ("%s \"%s,,,,%s\" %s", cmd_prefix, username, GOOROOM_ACCOUNT, username);
		}
	}

	g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL);

	g_free (cmd);

	if (is_user_exists (username))
		return TRUE;

	return FALSE;
}

static char *
get_wrapped_passphrase_file (const char *user)
{
	char *wrapped_pw_filename = NULL;
	struct passwd *user_entry = getpwnam (user);

	if (user_entry) {
		wrapped_pw_filename = g_strdup_printf ("%s/.ecryptfs/%s",
											   user_entry->pw_dir,
											   ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME);
	} else {
		wrapped_pw_filename = g_strdup_printf ("/home/%s/.ecryptfs/%s", user,
											   ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME);
	}

	return wrapped_pw_filename;
}

static char *
get_public_key_from_certificate ()
{
	char *pubkey = NULL;
	char *output = NULL;

	char *openssl = g_find_program_in_path ("openssl");
	if (openssl) {
		// openssl x509 -in /etc/ssl/certs/gooroom_client.crt -noout -pubkey
		char *cmd = g_strdup_printf ("%s x509 -in %s -noout -pubkey", openssl, GOOROOM_CERT);
		if (!g_spawn_command_line_sync (cmd, &output, NULL, NULL, NULL)) {
			syslog (LOG_ERR, "pam_grm_auth: Error running command to get public key [%s]", __FUNCTION__);
		}
		g_free (cmd);
	}

	g_free (openssl);

	if (output) {
		pubkey = g_strndup (output, strlen (output) - 1);
	}
	g_free (output);

	return pubkey;
}
 

static void
setuid_child_setup_func (gpointer data)
{
	struct passwd *pw = data;

	if (pw == NULL || initgroups (pw->pw_name, pw->pw_gid) != 0 ||
		setgid (pw->pw_gid) != 0 ||
		setuid (pw->pw_uid) != 0) {
		exit (1);
	}
}

static int
rewrap_passphrase (const char *user,
                   const char *file,
                   const char *old_wrapping_passphrase,
                   const char *new_wrapping_passphrase)
{
	int         status = -1;
	const char *argv[5];

	argv[0] = ECRYPTFS_REWRAP_PASSPHRASE_HELPER;
	argv[1] = file;
	argv[2] = old_wrapping_passphrase;
	argv[3] = new_wrapping_passphrase;
	argv[4] = NULL;

	struct passwd *pw = getpwnam (user);

	if (g_spawn_sync (NULL, (gchar **)argv, NULL, 0,
				(GSpawnChildSetupFunc)setuid_child_setup_func, pw,
				NULL, NULL, &status, NULL))
	{
		g_spawn_check_exit_status (status, NULL);
	}

	return status;
}

static int
wrap_passphrase (const char *user,
                 const char *file,
                 const char *wrapping_passphrase,
                 char       *passphrase)
{
	int         status = -1;
	const char *argv[5];

	argv[0] = ECRYPTFS_WRAP_PASSPHRASE_HELPER;
	argv[1] = file;
	argv[2] = passphrase;
	argv[3] = wrapping_passphrase;
	argv[4] = NULL;

	struct passwd *pw = getpwnam (user);

	if (g_spawn_sync (NULL, (gchar **)argv, NULL, 0,
				(GSpawnChildSetupFunc)setuid_child_setup_func, pw,
				NULL, NULL, &status, NULL))
	{
		g_spawn_check_exit_status (status, NULL);
	}

	return status;
}

static int
wrap_passphrase_file (const char *user,
                      const char *wrapped_pw_filename,
                      const char *passphrase,
                      const char *unwrapped_pw_filename)
{
	int         status = -1;
	const char *argv[5];

	argv[0] = ECRYPTFS_WRAP_PASSPHRASE_FILE_HELPER;
	argv[1] = wrapped_pw_filename;
	argv[2] = passphrase;
	argv[3] = unwrapped_pw_filename;
	argv[4] = NULL;

	struct passwd *pw = getpwnam (user);

	if (g_spawn_sync (NULL, (gchar **)argv, NULL, 0,
                      (GSpawnChildSetupFunc)setuid_child_setup_func, pw,
                      NULL, NULL, &status, NULL))
	{
		g_spawn_check_exit_status (status, NULL);
	}

	return status;
}

static gboolean
send_passphrase_to_online (const char *host, const char *token, char *base64_encoded_passphrase)
{
	CURL *curl;
	gboolean retval = FALSE;
	struct MemoryStruct chunk;

	if (!token || !base64_encoded_passphrase) {
		return FALSE;
	}

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *escaped_passphrase = g_uri_escape_string (base64_encoded_passphrase, NULL, TRUE);
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/passphrase", host);
		char *post_fields = g_strdup_printf ("login_token=%s&passphrase=%s", token, escaped_passphrase);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
		g_free (escaped_passphrase);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	char *data = g_strdup (chunk.memory);
	if (data) {
		retval = (is_result_ok (data)) ? TRUE : FALSE;
		g_free (data);
	}

	g_free (chunk.memory);

	return retval;
}

static gboolean
save_passphrase_for_ecryptfs (pam_handle_t *pamh, char *passphrase)
{
	gboolean ret = FALSE;
	char *public_key = NULL;
	int encrypted_passphrase_len = -1;
	unsigned char encrypted_passphrase[4098] = {0,};

	/* 1. Encrypting passphrase with public key */
	public_key = get_public_key_from_certificate ();
	if (!public_key) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get public key from certificate [%s]", __FUNCTION__);
		return FALSE;
	}

	encrypted_passphrase_len = encrypt_with_public_key ((unsigned char *)passphrase, strlen (passphrase), (unsigned char *)public_key, encrypted_passphrase);

	g_free (public_key);

	/* 2. Sending encrypted passphrase to online */
	if (encrypted_passphrase_len != -1) {
		char *base64_encoded_passphrase = g_base64_encode (encrypted_passphrase, encrypted_passphrase_len);
		if (base64_encoded_passphrase) {
			char *url = parse_url ();
			if (url) {
				const char *data;
				if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS)
					data = NULL;

				char *login_token = get_login_token (data);
				if (login_token) {
					if (send_passphrase_to_online (url, login_token, base64_encoded_passphrase)) {
						ret = TRUE;
					} else {
						syslog (LOG_ERR, "pam_grm_auth: Error attempting to send passphrase to online [%s]", __FUNCTION__);
					}
				} else {
					syslog (LOG_ERR, "pam_grm_auth: Error attempting to get login token [%s]", __FUNCTION__);
				}
				g_free (login_token);
			} else {
				syslog (LOG_ERR, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
			}
			g_free (url);
		} else {
			syslog (LOG_ERR, "pam_grm_auth: Base64 encoding error [%s]", __FUNCTION__);
		}
		g_free (base64_encoded_passphrase);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to encrypt passphrase with public key [%s]", __FUNCTION__);
	}

	return ret;
}

static char *
get_two_factor_hash_from_online (pam_handle_t *pamh, const char *host, const char *user, const char *password)
{
	CURL *curl;
	CURLcode res = CURLE_OK;
	char *data = NULL, *retval = NULL;
	struct MemoryStruct chunk;

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *pw_hash = create_hash (user, password, NULL);

		char *url = g_strdup_printf ("https://%s/glm/v1/pam/nfc", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to request authentication for NFC [%s]", __FUNCTION__);
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		goto done;
	}

	if (is_result_ok (data)) {
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
		if (jerr == json_tokener_success) {
			json_object *obj1 = NULL, *obj2 = NULL;
			obj1 = JSON_OBJECT_GET (root_obj, "data");
			obj2 = JSON_OBJECT_GET (obj1, "nfc_secret_data");
			if (obj2) {
				retval = g_strdup (json_object_get_string (obj2));
			}
			json_object_put (root_obj);
		}
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Authentication is failed for NFC [%s]", __FUNCTION__);
	}

	g_free (data);

done:
	g_free (chunk.memory);

	return retval;
}

static gboolean
user_logged_in (const char *username)
{
	gboolean logged_in = FALSE;
	char *cmd = g_find_program_in_path ("users");
	if (cmd) {
		char *outputs = NULL;
		g_spawn_command_line_sync (cmd, &outputs, NULL, NULL, NULL);
		if (outputs) {
			int i = 0;
			char **lines = g_strsplit (outputs, "\n", -1);
			for (i = 0; lines[i] != NULL; i++) {
				int j = 0;
				char **users = g_strsplit (lines[i], " ", -1);
				for (j = 0; users[j] != NULL; j++) {
					if (g_strcmp0 (users[j], username) == 0) {
						logged_in = TRUE;
						break;
					}
				}
				g_strfreev (users);

				if (logged_in)
					break;
			}
			g_strfreev (lines);
			g_free (outputs);
		}
		g_free (cmd);
	}

	return logged_in;
}

static int
check_auth (pam_handle_t *pamh, const char *host, const char *user, const char *password)
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
		char *pw_hash = create_hash (user, password, NULL);

		char *url = g_strdup_printf ("https://%s/glm/v1/pam/authconfirm", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to request authentication [%s]", __FUNCTION__);
		retval = PAM_AUTH_ERR;
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	retval = is_result_ok (data) ? PAM_SUCCESS : PAM_AUTH_ERR;

	g_free (data);

done:
	g_free (chunk.memory);

	return retval;
}

static int
login_from_online (pam_handle_t *pamh, const char *host, const char *user, const char *password, gboolean debug)
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
		char *pw_hash = create_hash (user, password, NULL);

		char *url = g_strdup_printf ("https://%s/glm/v1/pam/auth", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		retval = PAM_AUTH_ERR;
		if (res == CURLE_COULDNT_CONNECT) {
			syslog (LOG_ERR, "pam_grm_auth: Failed to connect to host or proxy [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Failed to connect to server"));
		} else if (res == CURLE_OPERATION_TIMEDOUT) {
			syslog (LOG_ERR, "pam_grm_auth: Operation timeout [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Operation timeout"));
		} else {
			syslog (LOG_ERR, "pam_grm_auth: Connection error [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Connection error"));
		}
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	if (debug) {
		FILE *fp = fopen ("/var/tmp/libpam_grm_auth_debug", "a+");
		fprintf (fp, "=================Received Data Start===================\n");
		fprintf (fp, "%s\n", data);
		fprintf (fp, "=================Received Data End=====================\n");
		fclose (fp);
	}

	if (is_result_ok (data)) {
		char *real = get_real_name (data);
		if (add_account (user, real)) {
			/* store data for future reference */
			pam_set_data (pamh, "user_data", g_strdup (chunk.memory), cleanup_data);

			/* for pam_mount */
			enum json_tokener_error jerr = json_tokener_success;
			json_object *root_obj = json_tokener_parse_verbose (data, &jerr);

			if (jerr == json_tokener_success) {
				json_object *obj1 = NULL, *obj2 = NULL;
				obj1 = JSON_OBJECT_GET (root_obj, "data");
				obj2 = JSON_OBJECT_GET (obj1, "desktopInfo");
				if (obj2) {
					make_mount_xml (obj2);
				}

				json_object_put (root_obj);
			}

			retval = PAM_SUCCESS;
		} else {
			syslog (LOG_ERR, "pam_grm_auth: Error attempting to create account [%s]", __FUNCTION__);
			retval = PAM_AUTH_ERR;
		}
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Authentication is failed [%s]", __FUNCTION__);
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

	if (!token || !host) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get url or login token [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/logout", host);
		char *post_fields = g_strdup_printf ("login_token=%s", token);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
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

static void
send_request_to_agent (pam_handle_t *pamh, const char *request, const char *user)
{
	GVariant   *variant;
	GDBusProxy *proxy;
	GError     *error = NULL;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE,
			NULL,
			"kr.gooroom.agent",
			"/kr/gooroom/agent",
			"kr.gooroom.agent",
			NULL,
			&error);

	if (proxy) {
		const char *json = "{\"module\":{\"module_name\":\"config\",\"task\":{\"task_name\":\"%s\",\"in\":{\"login_id\":\"%s\"}}}}";

		char *arg = g_strdup_printf (json, request, user);

		variant = g_dbus_proxy_call_sync (proxy, "do_task",
				g_variant_new ("(s)", arg),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

		g_free (arg);

		if (variant) {
			g_variant_unref (variant);
		} else {
			syslog (LOG_ERR, "pam_grm_auth: [%s : %s]", __FUNCTION__, error->message);
			g_error_free (error);
		}
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating proxy [%s : %s]", __FUNCTION__, error->message);
		g_error_free (error);
	}
}

static gboolean
rewrap_ecryptfs_passphrase_if_necessary (pam_handle_t *pamh, const char *user, const char *new_password)
{
	gboolean ret = FALSE;
	char *unwrapped_pw_filename = NULL;
	char *wrapped_passphrase_file = NULL;

	wrapped_passphrase_file = get_wrapped_passphrase_file (user);
	unwrapped_pw_filename = g_strdup_printf ("/dev/shm/.ecryptfs-%s", user);

	if (g_file_test (unwrapped_pw_filename, G_FILE_TEST_EXISTS)) {
		gchar *passphrase = NULL;
		g_file_get_contents (unwrapped_pw_filename, &passphrase, NULL, NULL);

		if (passphrase) {
			if (save_passphrase_for_ecryptfs (pamh, passphrase)) {
				if (wrap_passphrase_file (user, wrapped_passphrase_file, new_password, unwrapped_pw_filename) == 0) {
					ret = TRUE;
				} else {
					syslog (LOG_ERR, "pam_grm_auth: Error wrapping cleartext password [%s]", __FUNCTION__);
				}
			} else {
				syslog (LOG_ERR, "pam_grm_auth: Error attempting to save passphrase [%s]", __FUNCTION__);
			}
		} else {
			syslog (LOG_ERR, "pam_grm_auth: Error attempting to get random passphrase [%s]", __FUNCTION__);
		}

		g_free (passphrase);
		goto out;
	}

	const char *data;
	unsigned char passphrase[4098] = {0,};

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS)
		data = NULL;

	// get existing passphrase from online
	int result = get_passphrase_from_online (data, passphrase);
	if (result == 0) {
		// Rewrap passphrase with new password
		if (wrap_passphrase (user, wrapped_passphrase_file, new_password, (char *)passphrase) == 0)
			ret = TRUE;
	} else if (result == 1) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get base64 encoded passphrase from online [%s]", __FUNCTION__);
	}

out:
	g_free (wrapped_passphrase_file);
	g_free (unwrapped_pw_filename);

	return ret;
}

int
check_passwd_expiry (pam_handle_t *pamh, long lastchg, int maxdays)
{
	int daysleft = 9999;
	long curdays;

	curdays = (long)(time(NULL) / (60 * 60 * 24));

	if (lastchg == 0) {
		return 0;
	}

	daysleft = (gint)(lastchg - curdays) + maxdays;

	return daysleft;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	gboolean two_factor = FALSE, debug = FALSE;
	char *url = NULL;
	const char *user, *password;

	/* Initialize i18n */
//	setlocale (LC_ALL, "");
//	bindtextdomain (PACKAGE, LOCALEDIR);
//  bind_textdomain_codeset (PACKAGE, "UTF-8");
//  textdomain (PACKAGE);

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "debug") || !strcmp (*argv, "debug_on")) {
			debug = TRUE;
		} else if (!strcmp (*argv, "two_factor")) {
			two_factor = TRUE;
		} else if (!strncmp (*argv, "connection_timeout=", 19)) {
			if ((*argv)[19] != '\0') {
				CONNECTION_TIMEOUT = atoi (19 + *argv);
			}
		}
	}

	CONNECTION_TIMEOUT = (CONNECTION_TIMEOUT < 1) ? 30 : CONNECTION_TIMEOUT;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (!is_online_account (user)) {
		syslog (LOG_NOTICE, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_AUTH_ERR;
	}

	if (pam_get_item (pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS)
		return PAM_AUTH_ERR;

	if (user_logged_in (user)) {
		retval = check_auth (pamh, url, user, password);
	} else {
		retval = login_from_online (pamh, url, user, password, debug);
	}

	if (retval != PAM_SUCCESS)
		goto out;

	if (two_factor) {
		retval = PAM_AUTH_ERR;
		char *data = NULL;
		if (nfc_data_get (pamh, &data)) {
			if (data) {
				/* user name + nfc serial num + nfc data */
				char *user_plus_data = g_strdup_printf ("%s%s", user, data);
				char *user_plus_data_sha256 = sha256_hash (user_plus_data);
				char *two_factor_hash = get_two_factor_hash_from_online (pamh, url, user, password);

				if (user_plus_data_sha256 && two_factor_hash &&
					g_strcmp0 (user_plus_data_sha256, two_factor_hash) == 0) {
					retval = PAM_SUCCESS;
				} else {
					send_info_msg (pamh, _("Failure of the Two-Factor Authentication"));
				}

				g_free (user_plus_data);
				g_free (user_plus_data_sha256);
				g_free (two_factor_hash);
			}
		}
		g_free (data);
	}

	if (!user_logged_in (user)) {
		if (!rewrap_ecryptfs_passphrase_if_necessary (pamh, user, password)) {
			syslog (LOG_ERR, "pam_grm_auth : Failed to rewrap passphrase for ecryptfs [%s]", __FUNCTION__ );
			send_info_msg (pamh, _("Failed to rewrap passphrase for ecryptfs"));
			retval = PAM_AUTH_ERR;
		}
	}

out:
	g_free (url);

	return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

static int
rad_converse (pam_handle_t *pamh, int msg_style, char *message, char **password)
{ 
	const struct pam_conv *conv;
	struct pam_message resp_msg;
	const struct pam_message *msg[1];
	struct pam_response *resp = NULL;
	int retval;

	resp_msg.msg_style = msg_style;
	resp_msg.msg = message;
	msg[0] = &resp_msg;

	/* grab the password */
	retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
	if (retval != PAM_SUCCESS) { return retval; }

	retval = conv->conv (1, msg, &resp,conv->appdata_ptr);
	if (retval != PAM_SUCCESS) { return retval; }

	if (password) { /* assume msg.type needs a response */
		/* I'm not sure if this next bit is necessary on Linux */
		*password = resp->resp;
		free (resp);
	}

	return PAM_SUCCESS;
}

static gboolean
change_passphrase_for_ecryptfs (const char *user, const char *old_passphrase, const char *new_passphrase)
{
	gboolean ret = FALSE;
	gchar *wrapped_passphrase_file = NULL;

	wrapped_passphrase_file = get_wrapped_passphrase_file (user);
	if (g_file_test (wrapped_passphrase_file, G_FILE_TEST_EXISTS)) {
		if (rewrap_passphrase (user, wrapped_passphrase_file, old_passphrase, new_passphrase) == 0)
			ret = TRUE;
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get wrapped-passphrase file [%s]", __FUNCTION__);
	}
	g_free (wrapped_passphrase_file);

	return ret;
}


static gboolean
request_to_change_password (const gchar *user, const char *host, const gchar *token, const gchar *old_passwd, const gchar *new_passwd)
{
	CURL *curl;
	gboolean retval = FALSE;
	struct MemoryStruct chunk;

	if (!host || !token || !old_passwd || !new_passwd) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get information for changing password [%s]", __FUNCTION__);
		return FALSE;
	}

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *old_pw_hash = create_hash (user, old_passwd, NULL);
		char *new_pw_hash = create_hash (user, new_passwd, NULL);

		char *url = g_strdup_printf ("https://%s/glm/v1/pam/password", host);
		char *post_fields = g_strdup_printf ("password=%s&new_password=%s&login_token=%s", old_pw_hash, new_pw_hash, token);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt(curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

		/* Now specify the POST data */
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, post_fields);

		/* set timeout */
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, CONNECTION_TIMEOUT);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	char *data = g_strdup (chunk.memory);
	if (data) {
		retval = is_result_ok (data);
		g_free (data);
	}

	g_free (chunk.memory);

  return retval;
}

static gboolean
change_online_password (pam_handle_t *pamh, const char *user, const char *new_passwd)
{
	char *url = NULL;
	char *token = NULL;
	const char *old_passwd, *data;
	gboolean ret = FALSE;

	if (pam_get_item (pamh, PAM_OLDAUTHTOK ,(const void**)&old_passwd) != PAM_SUCCESS)
		return FALSE;

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS)
		return FALSE;

	token = get_login_token (data);
	if (!token) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get login token [%s]", __FUNCTION__);
		return FALSE;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		g_free (token);
		return FALSE;
	}

	ret = request_to_change_password (user, url, token, old_passwd, new_passwd);
	if (ret) {
		if (!change_passphrase_for_ecryptfs (user, old_passwd, new_passwd)) {
			syslog (LOG_ERR, "pam_grm_auth: Error attempting to change passphrase for ecryptfs [%s]", __FUNCTION__);
			ret = FALSE;
		}
#if 0
		/*  If the ecryptfs passphrase change fails, restore password */
		if (ret == FALSE) {
			gboolean restore = FALSE;
			int try = 1;
			while (try++ <= 3) {
				if (request_to_change_password (user, url, token, new_passwd, old_passwd)) {
					restore = TRUE;
					break;
				}
			}
			if (!restore) {
			}
		}
#endif
	}

	g_free (token);
	g_free (url);

	return ret;
}

static int
verify_current_password (pam_handle_t *pamh, const char *user, const char *password)
{
	char *url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_AUTHTOK_ERR;
	}

	if (check_auth (pamh, url, user, password) != PAM_SUCCESS) {
		return PAM_AUTHTOK_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	int retval = PAM_AUTHTOK_ERR;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (!is_online_account (user)) {
		syslog (LOG_NOTICE, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (flags & PAM_PRELIM_CHECK) {
		char *password = NULL;
		retval = rad_converse (pamh, PAM_PROMPT_ECHO_OFF, "Enter current password", &password);
		if (retval != PAM_SUCCESS) {
			g_free (password);
			return retval;
		}

		retval = verify_current_password (pamh, user, password);
		if (retval != PAM_SUCCESS) {
			g_free (password);
			return retval;
		}

		pam_set_item (pamh, PAM_OLDAUTHTOK, password);
		g_free (password);
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		int attempts = 0;
		char *new_password = NULL;
		char *chk_password = NULL;

		/* loop, trying to get matching new passwords */
		while (attempts++ < 3) {
			retval = rad_converse (pamh, PAM_PROMPT_ECHO_OFF, "Enter new password", &new_password);
			if (retval != PAM_SUCCESS) {
				goto error;
			}

			retval =  rad_converse (pamh, PAM_PROMPT_ECHO_OFF, "Retype new password", &chk_password);
			if (retval != PAM_SUCCESS) {
				goto error;
			}

			/* if they don't match, don't pass them to the next module */
			if (g_strcmp0 (new_password, chk_password) != 0) {
				send_info_msg (pamh, _("Passwords do not match."));
				PAM_FORGET (new_password);
				PAM_FORGET (chk_password);
				continue;
			}

			if (strlen (new_password) < 6) {
				send_info_msg (pamh, _("It's WAY too short."));
				PAM_FORGET (new_password);
				PAM_FORGET (chk_password);
				continue;
			}

			break;
		}

		if (attempts >= 3) { /* too many new password attempts: die */
			retval = PAM_AUTHTOK_ERR;
		} else {
			if (change_online_password (pamh, user, new_password)) {
				pam_set_item (pamh, PAM_AUTHTOK, new_password);
				retval = PAM_SUCCESS;
			} else {
				retval = PAM_AUTHTOK_ERR;
			}
		}
error:
		PAM_FORGET (new_password);
		PAM_FORGET (chk_password);
	}

	return retval;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (!is_online_account (user)) {
		syslog (LOG_NOTICE, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	if (!data) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	long lastchg;
	int daysleft, maxdays, warndays = 7;

	run_chage_l (data, &lastchg, &maxdays);

	if (lastchg == -1) {
		syslog (LOG_NOTICE, "pam_grm_auth : Temporarily issued password for %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "Temporary Password");
		return PAM_NEW_AUTHTOK_REQD;
	}

	if (lastchg == 0) {
		syslog (LOG_NOTICE, "pam_grm_auth : expired password for user %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "You are required to change your password immediately");
		return PAM_NEW_AUTHTOK_REQD;
	}

	daysleft = check_passwd_expiry (pamh, lastchg, maxdays);

	if (daysleft <= 0) {
		syslog (LOG_NOTICE, "pam_grm_auth : expired password for user %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "You are required to change your password immediately");
		return PAM_NEW_AUTHTOK_REQD;
	}

	if (daysleft >= 1 && daysleft <= warndays) {
		gchar *msg = NULL;
		if (daysleft == 1) {
			syslog (LOG_NOTICE, "pam_grm_auth : password for user %s will expire in %d day", user, daysleft);
		} else {
			syslog (LOG_NOTICE, "pam_grm_auth : password for user %s will expire in %d days", user, daysleft);
		}
		msg = g_strdup_printf ("Until Password Expiration:%d", daysleft);

		char *res = NULL;
		int retval = rad_converse (pamh, PAM_PROMPT_ECHO_OFF, msg, &res);
		g_free (msg);

		if (retval != PAM_SUCCESS || g_strcmp0 (res, "chpasswd_yes") != 0) {
			g_free (res);
			return PAM_SUCCESS;
		}

		g_free (res);

		return PAM_NEW_AUTHTOK_REQD;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int CLEANUP = 0;
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "cleanup")) {
			CLEANUP++;
			break;
		}
	}

	if (cleanup_function_enabled ())
		CLEANUP++;

	if (CLEANUP > 0)
		cleanup_users (user);

	if (!is_online_account (user)) {
		syslog (LOG_NOTICE, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	if (!data) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	/* wait for /var/run/user/$(uid) directory to be created */
	usleep (1000 * 200);

	/* make suer to make /var/run/user/$(uid)/gooroom directory */
	make_sure_to_create_save_dir (user);

	delete_config_files (user);

	struct passwd *user_entry = getpwnam (user);
	if (user_entry) {
		char *grm_user = g_strdup_printf ("/var/run/user/%d/gooroom/%s", user_entry->pw_uid, GRM_USER);
		g_file_set_contents (grm_user, data, -1, NULL);
		change_mode_and_owner (user, grm_user);
		g_free (grm_user);
	}

	/* request to save resource access rule for GOOROOM system */
	send_request_to_agent (pamh, "set_authority_config", user);

	/* request to check blocking packages change */
	send_request_to_agent (pamh, "get_update_operation_with_loginid", user);

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int CLEANUP = 0;
	int retval = PAM_IGNORE;
	char *url = NULL, *token = NULL;
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "cleanup")) {
			CLEANUP++;
			break;
		}
	}

	if (cleanup_function_enabled ())
		CLEANUP++;

	if (!is_online_account (user)) {
		syslog (LOG_NOTICE, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS)
		data = NULL;

	delete_config_files (user);

	retval = PAM_IGNORE;

	token = get_login_token (data);
	if (token != NULL) {
		retval = logout_from_online (url, token);
	} else {
		syslog (LOG_ERR, "pam_grm_auth: Error attempting to get login token [%s]", __FUNCTION__);
	}

	g_free (token);
	g_free (url);

	if (CLEANUP > 0)
		cleanup_users (NULL);

	return retval;
}
