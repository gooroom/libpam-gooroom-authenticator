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
#include "nfc_auth.h"
#include "pam_mount_template.h"
#include "custom-hash-helper.h"


#define GOOROOM_CERT					"/etc/ssl/certs/gooroom_client.crt"
#define GOOROOM_PRIVATE_KEY				"/etc/ssl/private/gooroom_client.key"
#define GRM_USER                        ".grm-user"
#define PAM_MOUNT_CONF_PATH             "/etc/security/pam_mount.conf.xml"
#define GOOROOM_MANAGEMENT_SERVER_CONF  "/etc/gooroom/gooroom-client-server-register/gcsr.conf"
#define GOOROOM_ONLINE_ACCOUNT          "gooroom-online-account"
#define DEFAULT_TIMEOUT					3

struct MemoryStruct {
	char *memory;
	size_t size;
};

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


static char *
create_hash (const char *user, const char *password, gpointer data)
{
	GError   *error        = NULL;
	GKeyFile *keyfile      = NULL;
	char     *str_hash     = NULL;
	char     *pw_system_type = NULL;

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
		if (tokens[4] && (g_strcmp0 (tokens[4], GOOROOM_ONLINE_ACCOUNT) == 0)) {
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
				syslog (LOG_WARNING, "pam_grm_auth: Error chown [%s]", __FUNCTION__);
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
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

			protocol_obj   = JSON_OBJECT_GET (mount_obj, "protocol");
			url_obj        = JSON_OBJECT_GET (mount_obj, "url");
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
	char *cmd = NULL;

	if (is_user_exists (username)) {
		cmd = g_strdup_printf ("/usr/bin/chfn -f %s", realname ? realname : username);
	} else {
		const char *cmd_prefix = "/usr/sbin/adduser --force-badname --shell /bin/bash --disabled-login --encrypt-home --gecos";
		if (realname) {
			cmd = g_strdup_printf ("%s \"%s,,,,%s\" %s", cmd_prefix, realname, GOOROOM_ONLINE_ACCOUNT, username);
		} else {
			cmd = g_strdup_printf ("%s \"%s,,,,%s\" %s", cmd_prefix, username, GOOROOM_ONLINE_ACCOUNT, username);
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
			syslog (LOG_WARNING, "pam_grm_auth: Error running command to get public key [%s]", __FUNCTION__);
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

static int
_unwrap_passphrase (char *file, const char *wrapping_passphrase, char *passphrase)
{
	int rc = 0;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	char *_wrapping_passphrase = g_strdup (wrapping_passphrase);

	if ((rc = ecryptfs_read_salt_hex_from_rc (salt_hex))) {
		from_hex (salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else {
		from_hex (salt, salt_hex, ECRYPTFS_SALT_SIZE);
	}

	rc = ecryptfs_unwrap_passphrase (passphrase, file, _wrapping_passphrase, salt);

	g_free (_wrapping_passphrase);

	return rc /* Returns 0 upon success. Negative upon error */;
}

static int
_wrap_passphrase (char *file, const char *wrapping_passphrase, char *passphrase)
{
	int rc = -1;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	char *_wrapping_passphrase = NULL;
	uid_t uid = 0, oeuid = 0;
    long ngroups_max = sysconf(_SC_NGROUPS_MAX);
    gid_t gid = 0, oegid = 0, groups[ngroups_max+1];
    int ngids = 0;
    pid_t child_pid, tmp_pid;

	oeuid = geteuid ();
	oegid = getegid ();
	if ((ngids = getgroups (sizeof(groups) / sizeof(gid_t), groups)) < 0) {
		syslog (LOG_WARNING, "pam_grm_auth: Error geteuid [%s]", __FUNCTION__);
		goto outnouid;
	}

	if (setegid (gid) < 0 || setgroups (1, &gid) < 0 || seteuid (uid) < 0) {
		syslog (LOG_WARNING, "pam_grm_auth: Error seteuid [%s]", __FUNCTION__);
		goto out;
	}

	_wrapping_passphrase = g_strdup (wrapping_passphrase);

	rc = 0;
	if ((child_pid = fork()) == 0) {
		/* temp regain uid 0 to drop privs */
		seteuid (oeuid);

		/* setgroups() already called */
		if (setgid (gid) < 0 || setuid (uid) < 0)
			goto out_child;

		if (ecryptfs_read_salt_hex_from_rc (salt_hex)) {
			from_hex (salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
		} else {
			from_hex (salt, salt_hex, ECRYPTFS_SALT_SIZE);
		}

		if (ecryptfs_wrap_passphrase (file, _wrapping_passphrase, salt, passphrase)) {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to wrap passphrase for ecryptfs [%s]", __FUNCTION__);
			goto out_child;
		}

out_child:
		exit(0);
	}

	if ((tmp_pid = waitpid (child_pid, NULL, 0)) == -1) {
		syslog (LOG_WARNING, "pam_grm_auth: waitpid() returned with error condition [%s]", __FUNCTION__);
	}

	g_free (_wrapping_passphrase);

out:
	seteuid (oeuid);
	setegid (oegid);
	setgroups (ngids, groups);

outnouid:
	return rc /* Returns 0 upon success. Negative upon error */;
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
		g_free (escaped_passphrase);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
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

static void
save_passphrase_for_ecryptfs (pam_handle_t *pamh, const char *user, const char *login_token)
{
	int rc = 0;
	int encrypted_passphrase_len = -1;
	char *wrapped_passphrase_file = NULL;
	unsigned char encrypted_passphrase[4098] = {0,};
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1] = {0,};

	/* 1. Getting passphrase from current wrapping_passphrase (wrapping_passphrase == password) */
	wrapped_passphrase_file = get_wrapped_passphrase_file (user);
	if (wrapped_passphrase_file && g_file_test (wrapped_passphrase_file, G_FILE_TEST_EXISTS)) {
		const char *password;
		/* Get the stored authtok here */
		if (pam_get_data (pamh, "grm_system_authtok", (const void**)&password) != PAM_SUCCESS) {
			password = NULL;
		}

		if (password) {
			rc = _unwrap_passphrase (wrapped_passphrase_file, password, passphrase);
		} else {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get password [%s]", __FUNCTION__);
		}
	}

	/* 2. Encrypting passphrase with public key */
	if (rc == 0) {
		char *public_key = NULL;
		public_key = get_public_key_from_certificate ();
		if (public_key) {
			encrypted_passphrase_len = encrypt_with_public_key ((unsigned char *)passphrase, strlen (passphrase), (unsigned char *)public_key, encrypted_passphrase);
		}
		g_free (public_key);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to unwrap passphrase for ecryptfs [%s]", __FUNCTION__);
	}

	/* 3. Sending encrypted passphrase to online */
	if (encrypted_passphrase_len != -1) {
		char *base64_encoded_passphrase = g_base64_encode (encrypted_passphrase, encrypted_passphrase_len);
		if (base64_encoded_passphrase) {
			char *url = parse_url ();
			if (url) {
				send_passphrase_to_online (url, login_token, base64_encoded_passphrase);
			} else {
				syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
			}
			g_free (url);
		} else {
			syslog (LOG_WARNING, "pam_grm_auth: Base64 encoding error [%s]", __FUNCTION__);
		}
		g_free (base64_encoded_passphrase);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to encrypt passphrase with public key [%s]", __FUNCTION__);
	}

	g_free (wrapped_passphrase_file);
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to request authentication for NFC [%s]", __FUNCTION__);
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
check_auth (pam_handle_t *pamh, const char *host, const char *user, const char *password, gboolean debug_on)
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to request authentication [%s]", __FUNCTION__);
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
login_from_online (pam_handle_t *pamh, const char *host, const char *user, const char *password, gboolean debug_on)
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		res = curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (pw_hash);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		retval = PAM_AUTH_ERR;
		if (res == CURLE_COULDNT_CONNECT) {
			syslog (LOG_WARNING, "pam_grm_auth: Failed to connect to host or proxy [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Failed to connect to server"));
		} else if (res == CURLE_OPERATION_TIMEDOUT) {
			syslog (LOG_WARNING, "pam_grm_auth: Operation timeout [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Operation timeout"));
		} else {
			syslog (LOG_WARNING, "pam_grm_auth: Connection error [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Connection error"));
		}
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	if (debug_on) {
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
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get url or login token [%s]", __FUNCTION__);
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
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, DEFAULT_TIMEOUT); /* 3 sec */
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_memory_callback);

		curl_easy_perform (curl);
		curl_easy_cleanup (curl);

		g_free (url);
		g_free (post_fields);
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating curl [%s]", __FUNCTION__);
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
			syslog (LOG_WARNING, "pam_grm_auth: [%s : %s]", __FUNCTION__, error->message);
			g_error_free (error);
		}
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error creating proxy [%s : %s]", __FUNCTION__, error->message);
		g_error_free (error);
	}
}

static gboolean
rewrap_ecryptfs_passphrase_if_necessary (pam_handle_t *pamh, const char *user, const char *new_password)
{
	const char *data;
	char *base64_encoded_passphrase = NULL;
	char *wrapped_passphrase_file = NULL;
	gboolean ret = TRUE;
	gboolean wrapped_passphrase_file_exist = FALSE;
	
	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	if (data) {
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
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
		return FALSE;
	}

	wrapped_passphrase_file = get_wrapped_passphrase_file (user);
	if (wrapped_passphrase_file && g_file_test (wrapped_passphrase_file, G_FILE_TEST_EXISTS)) {
		wrapped_passphrase_file_exist = TRUE;
	}

	// we have to rewrap passphrase with new password
	if (base64_encoded_passphrase && (g_strcmp0 (base64_encoded_passphrase, "") != 0) && wrapped_passphrase_file_exist) {
		char *private_key = NULL;
		int decrypted_length = -1;
		unsigned char *encrypted_passphrase = NULL;
		unsigned char decrypted_passphrase[4098] = {0,};

		if (!g_file_get_contents (GOOROOM_PRIVATE_KEY, &private_key, NULL, NULL)) {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get private key [%s]", __FUNCTION__);
			ret = FALSE;
			goto out;
		}

		if (!private_key) {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get private key [%s]", __FUNCTION__);
			ret = FALSE;
			goto out;
		}

		unsigned long out_len = 0;
		encrypted_passphrase = g_base64_decode (base64_encoded_passphrase, &out_len);
		if (!encrypted_passphrase) {
			syslog (LOG_WARNING, "pam_grm_auth: Base64 decoding error [%s]", __FUNCTION__);
			ret = FALSE;
			goto out;
		}

		decrypted_length = decrypt_with_private_key (encrypted_passphrase, 256, (unsigned char *)private_key, decrypted_passphrase);
		if (decrypted_length == -1) {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to decrypt passphrase with private key [%s]", __FUNCTION__);
			ret = FALSE;
		} else {
			if (_wrap_passphrase (wrapped_passphrase_file, new_password, (char *)decrypted_passphrase) != 0) {
				ret = FALSE;
			}
			change_mode_and_owner (user, wrapped_passphrase_file);
		}
		g_free (private_key);
	}

out:
	g_free (base64_encoded_passphrase);
	g_free (wrapped_passphrase_file);

	return ret;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	guint i;
	int retval;
	gboolean two_factor = FALSE, debug_on = FALSE;
	char *url = NULL;
	const char *user, *password;

	/* Initialize i18n */
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (LOG_WARNING, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	if (pam_get_item (pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS) {
		return PAM_SERVICE_ERR;
	}

	if (user_logged_in (user)) {
		retval = check_auth (pamh, url, user, password, debug_on);
	} else {
		retval = login_from_online (pamh, url, user, password, debug_on);
	}

	if (retval != PAM_SUCCESS) {
		goto out;
	}

	for (i = 0; i < argc; i++) {
		if (argv[i] != NULL) {
			if(g_str_equal (argv[i], "two_factor")) {
				two_factor = TRUE;
			} else if(g_str_equal (argv[i], "debug_on")) {
				debug_on = TRUE;
			}
		}
	}

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

		pam_set_data (pamh, "grm_system_authtok", strdup (password), cleanup_data);
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

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (LOG_WARNING, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (LOG_WARNING, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	if (!data) {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
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

	if (!user_logged_in (user)) {
		// get login token
		char *login_token = NULL;

		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
		if (jerr == json_tokener_success) {
			json_object *obj1 = NULL, *obj2 = NULL, *obj3= NULL;
			obj1 = JSON_OBJECT_GET (root_obj, "data");
			obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
			obj3 = JSON_OBJECT_GET (obj2, "login_token");
			if (obj3) {
				login_token = g_strdup (json_object_get_string (obj3));
			}
			json_object_put (root_obj);
		}

		if (login_token) {
			save_passphrase_for_ecryptfs (pamh, user, login_token);
		} else {
			syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get login token [%s]", __FUNCTION__);
		}

		g_free (login_token);
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
	int retval;
	char *url = NULL;
	const char *user, *data;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_grm_auth: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SERVICE_ERR;
	}

	if (!is_online_account (user)) {
		syslog (LOG_WARNING, "pam_grm_auth : Not an online account [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_IGNORE;
	}

	if (pam_get_data (pamh, "user_data", (const void**)&data) != PAM_SUCCESS) {
		data = NULL;
	}

	delete_config_files (user);

	retval = PAM_IGNORE;

	if (data) {
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (data, &jerr);

		if (jerr == json_tokener_success) {
			json_object *obj1 = NULL, *obj2 = NULL, *obj3= NULL;
			obj1 = JSON_OBJECT_GET (root_obj, "data");
			obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
			obj3 = JSON_OBJECT_GET (obj2, "login_token");
			if (obj3) {
				retval = logout_from_online (url, json_object_get_string (obj3));
			}

			json_object_put (root_obj);
		}
	} else {
		syslog (LOG_WARNING, "pam_grm_auth: Error attempting to get user_data [%s]", __FUNCTION__);
	}

	g_free (url);

	return retval;
}
