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
#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <fcntl.h>
#include <grp.h>
#include <locale.h>
#include <shadow.h>

#include <ecryptfs.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include "jwt.h"
#include "common.h"
#include "pam-common.h"
#include "nfc-auth.h"
#include "cleanup.h"
#include "pam-mount-template.h"
#include "pwquality-conf-template.h"

#define DAY_TO_SEC                (G_TIME_SPAN_DAY / G_TIME_SPAN_SECOND)
#define DEFAULT_WARNING_DAYS      7 // 7days
#define DEPT_EXPIRATION_CODE      "GR44"
#define ACCOUNT_EXPIRATION_CODE   "GR45"
#define ACCOUNT_LOCKING_CODE      "GR46"
#define LOGIN_TRIAL_EXCEED_CODE   "GR47"
#define DUPLICATE_LOGIN_CODE      "GR48"
#define PASSWORD_EXPIRATION_CODE  "GR49"
#define AUTH_FAILURE_CODE         "ELM002AUTHF"
#define DELETED_USER_CODE         "ELM003AUTHF"
#define PAM_MOUNT_CONF_PATH       "/etc/security/pam_mount.conf.xml"
#define PWQUALITY_CONF            "/etc/security/pwquality.conf"
#define PWQUALITY_CONF_ORG        "/etc/security/pwquality.conf.org"
#define GCSR_CONF                 "/etc/gooroom/gooroom-client-server-register/gcsr.conf"

#define PAM_FORGET(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}

enum {
	ACCOUNT_TYPE_LOCAL = 0,
	ACCOUNT_TYPE_GOOROOM,
	ACCOUNT_TYPE_GOOGLE,
	ACCOUNT_TYPE_NAVER
};

struct MemoryStruct {
	char *memory;
	size_t size;
};

typedef struct _PWQuality {
	char *minlen;
	char *dcredit;
	char *ucredit;
	char *lcredit;
	char *ocredit;
	char *difok;
	char *minclass;
} PWQuality;

typedef struct _DupClient {
	char *client_id;
	char *client_nm;
	char *ip;
	char *local_ip;
} DupClient;

typedef struct _Mount {
	char *url;
	char *mnt_point;
} Mount;

typedef struct _LoginData {
	char *user_id;
	char *user_name;
	char *email;
	char *login_token;
	char *encrypted_passphrase;
	char *acct_exp;
	char *dept_exp;
	char *pass_exp;

	int  acct_exp_remain;
	int  dept_exp_remain;
	int  pass_exp_remain;
	int  pw_max;
	gint64 pw_lastchg;

	gboolean pw_tmp;

	GList *mounts;

	PWQuality *pwquality;
	GList *dupclients;
} LoginData;


static gboolean DEBUG         = FALSE;
static gboolean TWO_FACTOR    = FALSE;
static gboolean user_real_added    = FALSE;
static const char *USER_PREFIX;

static int CONNECTION_TIMEOUT = 30; // Default Timeout: 30sec


json_object *
JSON_OBJECT_GET (json_object *root_obj, const char *key)
{
	if (!root_obj) return NULL;

	json_object *ret_obj = NULL;

	json_object_object_get_ex (root_obj, key, &ret_obj);

	return ret_obj;
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

static char *
get_hash (const char *user, const char *password, gpointer user_data)
{
	char *pw_hash = NULL;

	if (USER_PREFIX) {
		/* remove prefix from user*/
		if (strstr (user, USER_PREFIX) != NULL) {
			char *id = strstr (user, USER_PREFIX) + strlen (USER_PREFIX);
			pw_hash = create_hash (id, password, NULL);
		} else {
			pw_hash = create_hash (user, password, NULL);
		}
	} else {
		pw_hash = create_hash (user, password, NULL);
	}

	return pw_hash;
}

static gint64
str_to_sec (const char *date /* yyyy-mm-dd */)
{
	gint64 sec = 0;
	int year = 0, month = 0, day = 0;

	if ((date != NULL) && (strlen (date) == 10) &&
		(sscanf (date, "%d-%d-%d", &year, &month, &day) != 0)) {

		if (year != 0 && month != 0 && day != 0) {
			GDateTime *dt = g_date_time_new_local (year, month, day, 0, 0, 0);
			sec = g_date_time_to_unix (dt);
			g_date_time_unref (dt);

			return sec;
		}
	}

	GDateTime *dt = g_date_time_new_now_local ();
	sec = g_date_time_to_unix (dt);
	g_date_time_unref (dt);

	return sec;
}

static gboolean
make_sure_to_create_save_dir (const char *homedir)
{
	char *dir = NULL;
	gboolean ret = TRUE;

	dir = g_strdup_printf ("%s/.gooroom", homedir);

	g_mkdir_with_parents (dir, 0700);

	if (!g_file_test (dir, G_FILE_TEST_EXISTS)) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to create directory: [%s]", dir);
		ret = FALSE;
	}

	g_free (dir);

	return ret;
}

static void
change_mode_and_owner (uid_t uid, uid_t gid, const char *file)
{
	int fd = -1;
	char *cmd = NULL, *dir = NULL;

	if (!file) return;

	fd = open (file, O_WRONLY);
	if (fchmod (fd, 0600) == -1) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to change mode [%s]", file);
		goto failed;
	}

	dir = g_path_get_dirname (file);
	cmd = g_strdup_printf ("/bin/chown -R %d:%d %s", uid, gid, dir);

	if (!g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL))
		syslog (LOG_ERR, "pam_gooroom: Error attempting to change owner [%s]", dir);

	g_free (cmd);
	g_free (dir);

failed:
	close (fd);
}

static void
delete_config_files (const char *user)
{
	struct passwd *user_entry = getpwnam (user);
	if (user_entry) {
		char *cmd = g_strdup_printf ("/bin/rm -rf %s/.gooroom", user_entry->pw_dir);

		if (!g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL)) {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to delete directory: [%s/.gooroom]", user_entry->pw_dir);
		}

		g_free (cmd);
	}
}

static void
delete_ecryptfs_directory (const char *user)
{
	struct passwd *user_entry = getpwnam (user);
	if (user_entry) {
		char *cmd = g_strdup_printf ("/bin/rm -rf /home/.ecryptfs/%s", user);

		if (!g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL)) {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to delete directory: [home/.ecryptfs/%s]", user);
		}

		g_free (cmd);
	}
}

static void
restore_pwquality_file (void)
{
	if (g_file_test (PWQUALITY_CONF_ORG, G_FILE_TEST_EXISTS)) {
		GError *error = NULL;
		GFile *sfile, *dfile;

		/* MOVE /etc/security/pwquality.conf.org TO /etc/security/pwquality.conf */
		sfile = g_file_new_for_path (PWQUALITY_CONF_ORG);
		dfile = g_file_new_for_path (PWQUALITY_CONF);

		if (!g_file_move (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error)) {
			syslog (LOG_ERR, "pam_gooroom: Error moving pwquality.conf.org file: [%s]", error->message);
			g_error_free (error);
		}

		g_object_unref (sfile);
		g_object_unref (dfile);
	}
}

static void
save_login_data (struct passwd *user_entry, const char *data)
{
	char *grm_user = g_strdup_printf ("%s/.gooroom/%s", user_entry->pw_dir, GRM_USER);

	if (g_file_set_contents (grm_user, data, -1, NULL)) {
		change_mode_and_owner (user_entry->pw_uid, user_entry->pw_gid, grm_user);
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to save data to [%s]", grm_user);
	}
	g_free (grm_user);
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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK)
		return FALSE;

	return TRUE;
}

static GList *
get_dupclients (json_object *dupclients_obj)
{
	GList *list = NULL;

	if (!dupclients_obj)
		return NULL;

	int i = 0, len = 0;;
	len = json_object_array_length (dupclients_obj);

	for (i = 0; i < len; i++) {
		const char *val;
		json_object *p_obj[4] = {0,};
		json_object *dupclient_obj = json_object_array_get_idx (dupclients_obj, i);

		p_obj[0] = JSON_OBJECT_GET (dupclient_obj, "clientId");
		p_obj[1] = JSON_OBJECT_GET (dupclient_obj, "clientNm");
		p_obj[2] = JSON_OBJECT_GET (dupclient_obj, "ip");
		p_obj[3] = JSON_OBJECT_GET (dupclient_obj, "localIp");

		DupClient *dupclient = g_new0 (DupClient, 1);

		val = p_obj[0] ? json_object_get_string (p_obj[0]) : "";
		dupclient->client_id = g_strdup (val);
		val = p_obj[1] ? json_object_get_string (p_obj[1]) : "";
		dupclient->client_nm = g_strdup (val);
		val = p_obj[2] ? json_object_get_string (p_obj[2]) : "";
		dupclient->ip = g_strdup (val);
		val = p_obj[3] ? json_object_get_string (p_obj[3]) : "";
		dupclient->local_ip = g_strdup (val);

		list = g_list_append (list, dupclient);
	}

	return list;
}

static PWQuality *
get_pwquality (json_object *pwquality_obj)
{
	int minclass = 0;
	const char *val;
	PWQuality *pwquality;
	json_object *p_obj[6] = {0,};

	p_obj[0] = JSON_OBJECT_GET (pwquality_obj, "minlen");
	p_obj[1] = JSON_OBJECT_GET (pwquality_obj, "dcredit");
	p_obj[2] = JSON_OBJECT_GET (pwquality_obj, "ucredit");
	p_obj[3] = JSON_OBJECT_GET (pwquality_obj, "lcredit");
	p_obj[4] = JSON_OBJECT_GET (pwquality_obj, "ocredit");
	p_obj[5] = JSON_OBJECT_GET (pwquality_obj, "difok");

	pwquality = g_new0 (PWQuality, 1);

	val = p_obj[0] ? json_object_get_string (p_obj[0]) : "8";
	pwquality->minlen = g_strdup (val);
	val = p_obj[1] ? json_object_get_string (p_obj[1]) : "0";
	pwquality->dcredit = g_strdup (val);
	val = p_obj[2] ? json_object_get_string (p_obj[2]) : "0";
	pwquality->ucredit = g_strdup (val);
	val = p_obj[3] ? json_object_get_string (p_obj[3]) : "0";
	pwquality->lcredit = g_strdup (val);
	val = p_obj[4] ? json_object_get_string (p_obj[4]) : "0";
	pwquality->ocredit = g_strdup (val);
	val = p_obj[5] ? json_object_get_string (p_obj[5]) : "1";
	pwquality->difok = g_strdup (val);

	if (!g_str_equal (pwquality->dcredit, "0")) ++minclass;
	if (!g_str_equal (pwquality->ucredit, "0")) ++minclass;
	if (!g_str_equal (pwquality->lcredit, "0")) ++minclass;
	if (!g_str_equal (pwquality->ocredit, "0")) ++minclass;

	pwquality->minclass = g_strdup_printf ("%d", minclass);

	return pwquality;
}

static GList *
get_mounts (json_object *dt_obj)
{
	GList *list = NULL;
	json_object *mnts_obj = NULL;

	mnts_obj = JSON_OBJECT_GET (dt_obj, "mounts");
	if (mnts_obj) {
		int i = 0, len = 0;;
		len = json_object_array_length (mnts_obj);

		for (i = 0; i < len; i++) {
			json_object *mnt_obj = json_object_array_get_idx (mnts_obj, i);

			const char *val;
			json_object *p_obj[3] = {0,};

			p_obj[0] = JSON_OBJECT_GET (mnt_obj, "protocol");
			p_obj[1] = JSON_OBJECT_GET (mnt_obj, "url");
			p_obj[2] = JSON_OBJECT_GET (mnt_obj, "mountpoint");

			val = p_obj[0] ? json_object_get_string (p_obj[0]) : "";
			if (g_str_equal (val, "webdav")) {
				if (p_obj[1] && p_obj[2]) {
					Mount *mnt = g_new0 (Mount, 1);

					val = json_object_get_string (p_obj[1]);
					mnt->url = g_strdup (val);
					val = json_object_get_string (p_obj[2]);
					mnt->mnt_point = g_strdup (val);

					list = g_list_append (list, mnt);
				}
			}
		}
	}

	return list;
}

static gboolean
decrypt_passphrase (const char *i_passphrase, unsigned char *o_passphrase)
{
	gboolean ret = FALSE;
	char *private_key = NULL;
	char *base64_encoded_passphrase = NULL;

	base64_encoded_passphrase = g_uri_unescape_string (i_passphrase, NULL);

	if (!base64_encoded_passphrase || strlen (base64_encoded_passphrase) == 0) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get base64 encoded passphrase from online [%s]", __FUNCTION__);
		return FALSE;
	}

	g_file_get_contents (GOOROOM_PRIVATE_KEY, &private_key, NULL, NULL);
	if (private_key) {
		unsigned long outlen = 0;
		unsigned char *encrypted_passphrase = g_base64_decode (base64_encoded_passphrase, &outlen);
		if (encrypted_passphrase && outlen > 0) {
			int decrypted_length = decrypt_with_private_key (encrypted_passphrase, 256, (unsigned char *)private_key, o_passphrase);
			if (decrypted_length != -1) {
				ret = TRUE;
			} else {
				syslog (LOG_ERR, "pam_gooroom: Error attempting to decrypt passphrase with private key [%s]", __FUNCTION__);
			}
		} else {
			syslog (LOG_ERR, "pam_gooroom: Base64 decoding error [%s]", __FUNCTION__);
		}
		g_free (encrypted_passphrase);
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get private key [%s]", __FUNCTION__);
	}
	g_free (private_key);

	g_free (base64_encoded_passphrase);

	return ret;
}

static void
parse_login_data (LoginData *login_data, const char *data)
{
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);

	if (jerr == json_tokener_success) {
		const char *val;
		json_object *p_obj[14] = {0,};
		json_object *data_obj, *dt_info_obj, *login_info_obj;
		json_object *pwquality_obj, *dupclients_obj;

		data_obj = JSON_OBJECT_GET (root_obj, "data");
		login_info_obj = JSON_OBJECT_GET (data_obj, "loginInfo");
		pwquality_obj  = JSON_OBJECT_GET (data_obj, "passwordRule");
		dupclients_obj = JSON_OBJECT_GET (data_obj, "duplicateClients");
		dt_info_obj    = JSON_OBJECT_GET (data_obj, "desktopInfo");

		p_obj[0] = JSON_OBJECT_GET (login_info_obj, "user_id");
		p_obj[1] = JSON_OBJECT_GET (login_info_obj, "user_name");
		p_obj[2] = JSON_OBJECT_GET (login_info_obj, "email");
		p_obj[3] = JSON_OBJECT_GET (login_info_obj, "login_token");
		p_obj[4] = JSON_OBJECT_GET (login_info_obj, "pwd_last_day");
		p_obj[5] = JSON_OBJECT_GET (login_info_obj, "pwd_max_day");
		p_obj[6] = JSON_OBJECT_GET (login_info_obj, "pwd_temp_yn");
		p_obj[7] = JSON_OBJECT_GET (login_info_obj, "passphrase");
		p_obj[8] = JSON_OBJECT_GET (login_info_obj, "expire_dt"); //account expiration
		p_obj[9] = JSON_OBJECT_GET (login_info_obj, "expire_remain_day");
		p_obj[10] = JSON_OBJECT_GET (login_info_obj, "dept_expire_dt"); //division expiration
		p_obj[11] = JSON_OBJECT_GET (login_info_obj, "dept_expire_remain_day");
		p_obj[12] = JSON_OBJECT_GET (login_info_obj, "pwd_expire_dt"); //password expiration
		p_obj[13] = JSON_OBJECT_GET (login_info_obj, "pwd_expire_remain_day");

		val = p_obj[0] ? json_object_get_string (p_obj[0]) : "";
		login_data->user_id = g_strdup (val);

		val = p_obj[1] ? json_object_get_string (p_obj[1]) : "";
		login_data->user_name = g_strdup (val);

		val = p_obj[2] ? json_object_get_string (p_obj[2]) : "";
		login_data->email = g_strdup (val);

		val = p_obj[3] ? json_object_get_string (p_obj[3]) : "";
		login_data->login_token = g_strdup (val);

		val = p_obj[6] ? json_object_get_string (p_obj[6]) : "";
		if (g_str_equal (val, "Y")) {
			login_data->pw_tmp = TRUE;
			login_data->pw_lastchg = -1;
			login_data->pw_max = 99999;
		} else {
			login_data->pw_tmp = FALSE;

			val = p_obj[4] ? json_object_get_string (p_obj[4]) : "";
			login_data->pw_lastchg = str_to_sec (val);
			login_data->pw_max = p_obj[5] ? json_object_get_int (p_obj[5]) : 99999;
		}

		val = p_obj[7] ? json_object_get_string (p_obj[7]) : "";
		login_data->encrypted_passphrase = g_strdup (val);

		val = p_obj[8] ? json_object_get_string (p_obj[8]) : "";
		login_data->acct_exp = g_strdup (val);

		val = p_obj[9] ? json_object_get_string (p_obj[9]) : "";
		login_data->acct_exp_remain = (g_str_equal (val, "")) ? 99999 : json_object_get_int (p_obj[9]);

		val = p_obj[10] ? json_object_get_string (p_obj[10]) : "";
		login_data->dept_exp = g_strdup (val);

		val = p_obj[11] ? json_object_get_string (p_obj[11]) : "";
		login_data->dept_exp_remain = (g_str_equal (val, "")) ? 99999 : json_object_get_int (p_obj[11]);

		val = p_obj[12] ? json_object_get_string (p_obj[12]) : "";
		login_data->pass_exp = g_strdup (val);

		val = p_obj[13] ? json_object_get_string (p_obj[13]) : "";
		login_data->pass_exp_remain = (g_str_equal (val, "")) ? 99999 : json_object_get_int (p_obj[13]);

		login_data->mounts = get_mounts (dt_info_obj);
		login_data->pwquality = get_pwquality (pwquality_obj);
		login_data->dupclients = get_dupclients (dupclients_obj);
	}
}

static int
get_account_type (const char *user)
{
	int account_type = ACCOUNT_TYPE_LOCAL;
	struct passwd *user_entry = getpwnam (user);

	if (!user_entry) {
		if (!g_file_test ("/tmp/.gooroom-greeter-cloud-login", G_FILE_TEST_EXISTS))
			return ACCOUNT_TYPE_GOOROOM;

		char *contents = NULL;
		g_file_get_contents ("/tmp/.gooroom-greeter-cloud-login", &contents, NULL, NULL);
		if (contents) {
			if (g_str_equal (contents, "LOGIN_GOOGLE")) {
				account_type = ACCOUNT_TYPE_GOOGLE;
			} else if (g_str_equal (contents, "LOGIN_NAVER")) {
				account_type = ACCOUNT_TYPE_NAVER;
			}
		} else {
			account_type = ACCOUNT_TYPE_GOOROOM;
		}
		g_free (contents);

		return account_type;
	}

	char **tokens = g_strsplit (user_entry->pw_gecos, ",", -1);
	if (tokens && (g_strv_length (tokens) > 4)) {
		if (tokens[4]) {
			if (g_str_equal (tokens[4], GOOROOM_ACCOUNT)) {
				account_type = ACCOUNT_TYPE_GOOROOM;
			} else if (g_str_equal (tokens[4], GOOGLE_ACCOUNT)) {
				account_type = ACCOUNT_TYPE_GOOGLE;
			} else if (g_str_equal (tokens[4], NAVER_ACCOUNT)) {
				account_type = ACCOUNT_TYPE_NAVER;
			} else {
				account_type = ACCOUNT_TYPE_LOCAL;
			}
		}
	}

	g_strfreev (tokens);

	return account_type;
}

static void
create_config_for_pam_pwquality (PWQuality *pwquality)
{
	if (!pwquality) return;

	GFile *sfile, *dfile;
	GString *contents = NULL;

	if (g_file_test (PWQUALITY_CONF, G_FILE_TEST_EXISTS)) {
		GError *error = NULL;

		/* MOVE /etc/security/pwquality.conf TO /etc/security/pwquality.conf.org */
		sfile = g_file_new_for_path (PWQUALITY_CONF);
		dfile = g_file_new_for_path (PWQUALITY_CONF_ORG);

		if (!g_file_move (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error)) {
			syslog (LOG_ERR, "pam_gooroom: Error moving pwquality.conf file: [%s]", error->message);
			g_error_free (error);
			goto done;
		}
	}

	contents = g_string_new (NULL);

	g_string_printf (contents, pwquality_conf_data,
			pwquality->difok,
			pwquality->minlen,
			pwquality->dcredit,
			pwquality->ucredit,
			pwquality->lcredit,
			pwquality->ocredit,
			pwquality->minclass);

	char *str = g_string_free (contents, FALSE);
	if (!g_file_set_contents (PWQUALITY_CONF, str, -1, NULL)) {
		/* MOVE /etc/security/pwquality.conf.org TO /etc/security/pwquality.conf */
		g_file_move (dfile, sfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, NULL);
	}
	g_free (str);

done:
	g_object_unref (sfile);
	g_object_unref (dfile);
}

static void
create_xml_for_pam_mount (GList *mounts)
{
	GList *l = NULL;
	GString *pam_mount_xml;

	if (!mounts)
		return;

	if (!g_file_test (PAM_MOUNT_CONF_PATH, G_FILE_TEST_EXISTS))
		return;

	pam_mount_xml = g_string_new (NULL);

	g_string_append (pam_mount_xml, pam_mount_xml_template_prefix);
	for (l = mounts; l; l = l->next) {
		Mount *mnt = (Mount *)l->data;
		char *volume_def_data = g_strdup_printf (pam_mount_volume_definitions,
                                                 mnt->url, mnt->mnt_point);
		g_string_append (pam_mount_xml, volume_def_data);
		g_free (volume_def_data);
	}
	g_string_append (pam_mount_xml, pam_mount_xml_template_suffix);

	char *str = g_strdup (pam_mount_xml->str);
	g_file_set_contents (PAM_MOUNT_CONF_PATH, str, -1, NULL);
	g_free (str);

	g_string_free (pam_mount_xml, TRUE);
}

static gboolean
is_result_ok (char *json_data)
{
	gboolean ret = FALSE;
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json_data, &jerr);

	if (jerr == json_tokener_success) {
		const char *result;
		json_object *obj1, *obj2;

		obj1 = JSON_OBJECT_GET (root_obj, "status");
		obj2 = JSON_OBJECT_GET (obj1, "result");

		result = obj2 ? json_object_get_string (obj2) : "";

		ret = g_str_equal (result, "SUCCESS");

		json_object_put (root_obj);
	}

	return ret;
}

static gboolean
is_auth_ok (char *json_data, char **res_code, char **remaining_retry)
{
	gboolean ret = FALSE;
	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json_data, &jerr);

	if (jerr == json_tokener_success) {
		const char *val;
		json_object *obj1, *obj1_1, *obj2, *p_obj2[2] = {0,};

		obj1 = JSON_OBJECT_GET (root_obj, "data");
		obj2 = JSON_OBJECT_GET (root_obj, "status");

		obj1_1 = JSON_OBJECT_GET (obj1, "remainLoginTrial");

		p_obj2[0] = JSON_OBJECT_GET (obj2, "result");
		p_obj2[1] = JSON_OBJECT_GET (obj2, "resultCode");

		if (remaining_retry != NULL)
			*remaining_retry = obj1_1 ? g_strdup (json_object_get_string (obj1_1)) : g_strdup ("0");

		val = p_obj2[0] ? json_object_get_string (p_obj2[0]) : "";
		ret = g_str_equal (val, "SUCCESS");

		if (res_code != NULL)
			*res_code = p_obj2[1] ? g_strdup (json_object_get_string (p_obj2[1])) : g_strdup ("UNKNOWN");

		json_object_put (root_obj);
	}

	return ret;
}

static void
cleanup_raw_data (pam_handle_t *pamh, void *data, int pam_end_status)
{
	g_free (data);
}

static void
cleanup_data (pam_handle_t *pamh, void *data, int pam_end_status)
{
	LoginData *ld = (LoginData *)data;
	g_free (ld->user_id);
	g_free (ld->user_name);
	g_free (ld->email);
	g_free (ld->login_token);
	g_free (ld->encrypted_passphrase);
	g_free (ld->acct_exp);
	g_free (ld->dept_exp);

	GList *l = NULL;
	for (l = ld->mounts; l; l = l->next) {
		Mount *mnt = (Mount *)l->data;
		g_free (mnt->url);
		g_free (mnt->mnt_point);
		g_free (mnt);
	}
	g_list_free (ld->mounts);

	g_free (ld);
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
del_account (const char *username)
{
	if (is_user_exists (username)) {
		char *cmd = g_strdup_printf ("/usr/sbin/userdel -rf %s", username);
		g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL);
		g_free (cmd);
	}

	if (is_user_exists (username))
		return FALSE;

	return TRUE;
}

static gboolean
add_account (const char *username, const char *realname)
{
	char *cmd = NULL;

	if (is_user_exists (username)) {
		user_real_added = FALSE;
		cmd = g_strdup_printf ("/usr/bin/chfn -f %s %s", (realname ? realname : username), username);
	} else {
		user_real_added = TRUE;
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
			syslog (LOG_ERR, "pam_gooroom: Error running command to get public key [%s]", __FUNCTION__);
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

	if (g_spawn_sync (NULL, (char **)argv, NULL, 0,
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

	if (g_spawn_sync (NULL, (char **)argv, NULL, 0,
                      (GSpawnChildSetupFunc)setuid_child_setup_func, pw,
                      NULL, NULL, &status, NULL))
	{
		g_spawn_check_exit_status (status, NULL);
	}

	return status;
}

static gboolean
send_passphrase_to_online (const char *host, const char *login_token, const char *base64_encoded_passphrase)
{
	CURL *curl;
	gboolean retval = FALSE;
	struct MemoryStruct chunk;

	if (!login_token || !base64_encoded_passphrase) {
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
		char *post_fields = g_strdup_printf ("login_token=%s&passphrase=%s", login_token, escaped_passphrase);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
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
save_passphrase_to_online (pam_handle_t *pamh, const char *login_token, const char *passphrase)
{
	gboolean ret = FALSE;
	char *public_key = NULL;
	int encrypted_passphrase_len = -1;
	unsigned char encrypted_passphrase[4098] = {0,};

	/* 1. Encrypting passphrase with public key */
	public_key = get_public_key_from_certificate ();
	if (!public_key) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get public key from certificate [%s]", __FUNCTION__);
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
				if (send_passphrase_to_online (url, login_token, base64_encoded_passphrase)) {
					ret = TRUE;
				} else {
					syslog (LOG_ERR, "pam_gooroom: Error attempting to send passphrase to online [%s]", __FUNCTION__);
				}
			} else {
				syslog (LOG_ERR, "pam_gooroom: Error attempting to get online url [%s]", __FUNCTION__);
			}
			g_free (url);
		} else {
			syslog (LOG_ERR, "pam_gooroom: Base64 encoding error [%s]", __FUNCTION__);
		}
		g_free (base64_encoded_passphrase);
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to encrypt passphrase with public key [%s]", __FUNCTION__);
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
		char *pw_hash = get_hash (user, password, NULL);
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/nfc", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to request authentication for NFC [%s]", __FUNCTION__);
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
			json_object *obj1, *obj2;

			obj1 = JSON_OBJECT_GET (root_obj, "data");
			obj2 = JSON_OBJECT_GET (obj1, "nfc_secret_data");

			retval = obj2 ? g_strdup (json_object_get_string (obj2)) : NULL;

			json_object_put (root_obj);
		}
	} else {
		syslog (LOG_ERR, "pam_gooroom: Authentication is failed for NFC [%s]", __FUNCTION__);
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

static gboolean
cb_out_watch (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	gchar *string;
	gsize  size;

	if (cond == G_IO_HUP) {
		g_io_channel_unref (channel);
		return FALSE;
	}

	g_io_channel_read_line (channel, &string, &size, NULL, NULL);

	g_free (string);

	return TRUE;
}

static int
check_auth (pam_handle_t *pamh, const char *host, const char *user, const char *password)
{
	char *data = NULL;
	int retval = PAM_IGNORE;

	if (geteuid () != 0) {
		char *cmd = NULL;
		if (USER_PREFIX) {
			cmd = g_strdup_printf ("%s --user \'%s\' --password \'%s\' --user-prefix \'%s\'",
                                   GRM_AUTH_CHECK_HELPER, user, password, USER_PREFIX);
		} else {
			cmd = g_strdup_printf ("%s --user \'%s\' --password \'%s\'",
                                   GRM_AUTH_CHECK_HELPER, user, password);
		}
		g_spawn_command_line_sync (cmd, &data, NULL, NULL, NULL);
		g_free (cmd);
	} else {
		CURL *curl;
		CURLcode res = CURLE_OK;
		struct MemoryStruct chunk;

		chunk.size = 0;
		chunk.memory = malloc (1);

		curl_global_init (CURL_GLOBAL_ALL);

		/* get a curl handle */
		curl = curl_easy_init ();

		if (curl) {
			char *pw_hash = get_hash (user, password, NULL);
			char *url = g_strdup_printf ("https://%s/glm/v1/pam/authconfirm", host);
			char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

			curl_easy_setopt (curl, CURLOPT_URL, url);
			curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
			curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
			syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
		}

		curl_global_cleanup ();

		if (res != CURLE_OK) {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to request authentication [%s]", __FUNCTION__);
			retval = PAM_AUTH_ERR;
			goto done;
		}

		data = g_strdup (chunk.memory);
		g_free (chunk.memory);
	}

	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	char *res_code, *remaining_retry;

	if (!is_auth_ok (data, &res_code, &remaining_retry)) {
		g_free (res_code);
		g_free (remaining_retry);

		retval = PAM_AUTH_ERR;

		syslog (LOG_ERR, "pam_gooroom: Authentication is failed [%s]", __FUNCTION__);
	} else {
		retval = PAM_SUCCESS;
	}

	g_free (data);

done:
	return retval;
}

static int
verify_current_password (pam_handle_t *pamh, const char *user, const char *password)
{
	char *url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_AUTHTOK_RECOVERY_ERR;
	}

	if (check_auth (pamh, url, user, password) != PAM_SUCCESS) {
		return PAM_AUTHTOK_RECOVERY_ERR;
	}

	return PAM_SUCCESS;
}

static int
login_from_online (pam_handle_t *pamh, const char *host, const char *user, const char *password)
{
	CURL *curl;
	CURLcode res = CURLE_OK;
	char *data = NULL;
	char *res_code, *remaining_retry;
	int retval = PAM_IGNORE;
	struct MemoryStruct chunk;

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *pw_hash = get_hash (user, password, NULL);
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/auth", host);
		char *post_fields = g_strdup_printf ("user_id=%s&user_pw=%s", user, pw_hash);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
	}

	curl_global_cleanup ();

	if (res != CURLE_OK) {
		retval = PAM_AUTH_ERR;
		if (res == CURLE_COULDNT_CONNECT) {
			syslog (LOG_ERR, "pam_gooroom: Failed to connect to host or proxy [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Failed to connect to server"));
		} else if (res == CURLE_OPERATION_TIMEDOUT) {
			syslog (LOG_ERR, "pam_gooroom: Operation timeout [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Operation timeout"));
		} else {
			syslog (LOG_ERR, "pam_gooroom: Connection error [%s]", __FUNCTION__);
			send_info_msg (pamh, _("Connection error"));
		}
		goto done;
	}

	data = g_strdup (chunk.memory);
	if (!data) {
		retval = PAM_AUTH_ERR;
		goto done;
	}

	if (DEBUG) {
		syslog (LOG_DEBUG, "pam_gooroom: Received Data: %s", data);
	}

	pam_set_data (pamh, "login_raw_data", g_strdup (data), cleanup_raw_data);

	if (is_auth_ok (data, &res_code, &remaining_retry)) {
		LoginData *login_data = g_new0 (LoginData, 1);

		parse_login_data (login_data, data);

		if (add_account (user, login_data->user_name)) {
			/* store data for future reference */
			pam_set_data (pamh, "login_data", login_data, cleanup_data);

			/* for pam_mount */
			create_xml_for_pam_mount (login_data->mounts);

			/* for pam_pwquality */
			create_config_for_pam_pwquality (login_data->pwquality);

			retval = PAM_SUCCESS;
		} else {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to create account [%s]", __FUNCTION__);
			retval = PAM_AUTH_ERR;
		}
	} else {
		syslog (LOG_ERR, "pam_gooroom: Authentication is failed : Code [%s]", res_code);

		char *msg = NULL;
		if (g_str_equal (res_code, AUTH_FAILURE_CODE)) {
			if (g_str_equal (remaining_retry, "0")) {
				msg = g_strdup ("Account Locking");
			} else {
				msg = g_strdup_printf ("Authentication Failure:%s", remaining_retry);
			}
		} else if (g_str_equal (res_code, DELETED_USER_CODE)) {
			delete_ecryptfs_directory (user);
			if (!del_account (user))
				syslog (LOG_ERR, "pam_gooroom: Failed to delete account [%s]", user);
			msg = g_strdup_printf ("Authentication Failure");
		} else if (g_str_equal (res_code, DUPLICATE_LOGIN_CODE)) {
			msg = g_strdup ("Duplicate Login");
		} else if (g_str_equal (res_code, ACCOUNT_LOCKING_CODE)) {
			msg = g_strdup ("Account Locking");
		} else if (g_str_equal (res_code, ACCOUNT_EXPIRATION_CODE)) {
			msg = g_strdup ("Account Expiration");
		} else if (g_str_equal (res_code, PASSWORD_EXPIRATION_CODE)) {
			msg = g_strdup ("Password Expiration");
		} else if (g_str_equal (res_code, DEPT_EXPIRATION_CODE)) {
			msg = g_strdup ("Division Expiration");
		} else if (g_str_equal (res_code, LOGIN_TRIAL_EXCEED_CODE)) {
			msg = g_strdup ("Login Trial Exceed");
		}

		if (msg) {
			pam_prompt (pamh, PAM_ERROR_MSG, NULL, "%s", msg);
			g_free (msg);
		}

		retval = PAM_AUTH_ERR;
	}

	g_free (res_code);
	g_free (remaining_retry);
	g_free (data);

done:
	g_free (chunk.memory);

	return retval;
}

static gboolean
logout_from_online (const char *host, const char *token)
{
	CURL *curl;
	gboolean retval = FALSE;
	struct MemoryStruct chunk;

	if (!token || !host) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get url or login token [%s]", __FUNCTION__);
		return FALSE;
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
		curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
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
ensure_check_unwrapped_pw_file (char *unwrapped_pw_filename)
{
	int try = 0;

	// waiting for 2 secs
	for (;;) {
		if (g_file_test (unwrapped_pw_filename, G_FILE_TEST_EXISTS))
			return TRUE;

		if (try++ >= 40)
			break;

		g_usleep (G_USEC_PER_SEC / 20); // waiting for 1/20 sec
	}

	return FALSE;
}

static gboolean
rewrap_ecryptfs_passphrase_if_necessary (pam_handle_t *pamh, const char *user, const char *new_password)
{
	gboolean ret = FALSE;
	LoginData *login_data;
	char *unwrapped_pw_filename = NULL;
	char *wrapped_passphrase_file = NULL;
	unsigned char passphrase[4098] = {0,};

	if (pam_get_data (pamh, "login_data", (const void**)&login_data) != PAM_SUCCESS)
		return FALSE;

	wrapped_passphrase_file = get_wrapped_passphrase_file (user);
	unwrapped_pw_filename = g_strdup_printf ("/dev/shm/.ecryptfs-%s", user);

	if (user_real_added) {
		if (!ensure_check_unwrapped_pw_file (unwrapped_pw_filename)) {
			syslog (LOG_ERR, "pam_gooroom: Couldn't find %s file [%s]", unwrapped_pw_filename, __FUNCTION__);
			ret = FALSE;
			goto out;
		}
	}

	if (g_file_test (unwrapped_pw_filename, G_FILE_TEST_EXISTS)) {
		char *passphrase = NULL;
		g_file_get_contents (unwrapped_pw_filename, &passphrase, NULL, NULL);

		if (passphrase) {
			if (save_passphrase_to_online (pamh, login_data->login_token, passphrase)) {
				if (wrap_passphrase_file (user, wrapped_passphrase_file, new_password, unwrapped_pw_filename) == 0) {
					ret = TRUE;
				} else {
					syslog (LOG_ERR, "pam_gooroom: Error wrapping cleartext password [%s]", __FUNCTION__);
				}
			} else {
				syslog (LOG_ERR, "pam_gooroom: Error attempting to save passphrase [%s]", __FUNCTION__);
			}
		} else {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to get random passphrase [%s]", __FUNCTION__);
		}

		g_free (passphrase);

		goto out;
	}

	// get existing passphrase from online
	if (decrypt_passphrase (login_data->encrypted_passphrase, passphrase)) {
		// Rewrap passphrase with new password
		if (wrap_passphrase (user, wrapped_passphrase_file, new_password, (char *)passphrase) == 0)
			ret = TRUE;
	}

out:
	g_free (wrapped_passphrase_file);
	g_free (unwrapped_pw_filename);

	return ret;
}

static gint64
check_passwd_expiry (pam_handle_t *pamh, gint64 lastchg, int maxdays)
{
	gint64 cursec = 0;
	gint64 leftsec = 0;

	if (lastchg == 0)
		return 0;

	GDateTime *dt = g_date_time_new_now_local ();
	cursec = g_date_time_to_unix (dt);
	g_date_time_unref (dt);

	leftsec = (lastchg - cursec) + (maxdays * DAY_TO_SEC);

	return leftsec;
}

static char *
get_value_for (const char *json, const char *property)
{
	char *id_token = NULL;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (json, &jerr);

	if (jerr == json_tokener_success) {
		json_object *obj = NULL;
		obj = JSON_OBJECT_GET (root_obj, property);
		id_token = obj ? g_strdup (json_object_get_string (obj)) : NULL;
		json_object_put (root_obj);
	}

	return id_token;
}

static int 
handle_gooroom_authenticate (pam_handle_t *pamh, const char *user)
{
	int retval = PAM_AUTH_ERR;
	char *url = NULL;
	const char *password;

	url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_gooroom : Error attempting to get online url [%s]", __FUNCTION__);
		return PAM_AUTH_ERR;
	}

	if (pam_get_item (pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS)
		return PAM_AUTH_ERR;

	/* for unlocking screensaver */
	if (user_logged_in (user)) {
		retval = check_auth (pamh, url, user, password);
	} else {
		retval = login_from_online (pamh, url, user, password);
	}

	if (retval != PAM_SUCCESS)
		goto out;

	if (TWO_FACTOR) {
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
			syslog (LOG_ERR, "pam_gooroom : Failed to rewrap passphrase for ecryptfs [%s]", __FUNCTION__ );
			send_info_msg (pamh, _("Failed to rewrap passphrase for ecryptfs"));
			retval = PAM_AUTH_ERR;
		}
	}

out:
	g_free (url);

	return retval;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	int account_type = ACCOUNT_TYPE_LOCAL;
	const char *user;
	gboolean have_user_prefix = FALSE;

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "debug") || !strcmp (*argv, "debug_on")) {
			DEBUG = TRUE;
		} else if (!strcmp (*argv, "two_factor")) {
			TWO_FACTOR = TRUE;
		} else if (!strncmp (*argv, "connection_timeout=", 19)) {
			if ((*argv)[19] != '\0') {
				CONNECTION_TIMEOUT = atoi (19 + *argv);
			}
		} else if (!strncmp (*argv, "user_prefix=", 12)) {
			if ((*argv)[12] != '\0') {
				USER_PREFIX = (12 + *argv);
				have_user_prefix = TRUE;
			}
		}
	}

	if (!have_user_prefix)
		USER_PREFIX = NULL;

	CONNECTION_TIMEOUT = (CONNECTION_TIMEOUT < 1) ? 30 : CONNECTION_TIMEOUT;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	switch (get_account_type (user))
	{
		case ACCOUNT_TYPE_GOOROOM:
			retval = handle_gooroom_authenticate (pamh, user);
		break;

		default:
			retval = PAM_USER_UNKNOWN;
		break;
	}

	return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

static gboolean
request_to_change_password (const char *user, const char *host, const char *token, const char *old_passwd, const char *new_passwd)
{
	CURL *curl;
	gboolean retval = FALSE;
	struct MemoryStruct chunk;

	if (!host || !token || !old_passwd || !new_passwd) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get information for changing password [%s]", __FUNCTION__);
		return FALSE;
	}

	chunk.size = 0;
	chunk.memory = malloc (1);

	curl_global_init (CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init ();

	if (curl) {
		char *old_pw_hash = get_hash (user, old_passwd, NULL);
		char *new_pw_hash = get_hash (user, new_passwd, NULL);
		char *url = g_strdup_printf ("https://%s/glm/v1/pam/password", host);
		char *post_fields = g_strdup_printf ("password=%s&new_password=%s&login_token=%s", old_pw_hash, new_pw_hash, token);

		curl_easy_setopt (curl, CURLOPT_URL, url);
		curl_easy_setopt (curl, CURLOPT_SSLCERT, GOOROOM_CERT);
		curl_easy_setopt (curl, CURLOPT_SSLKEY, GOOROOM_PRIVATE_KEY);

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
		syslog (LOG_ERR, "pam_gooroom: Error creating curl [%s]", __FUNCTION__);
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
	LoginData *login_data;
	const char *old_passwd;
	gboolean ret = FALSE;

	if (pam_get_item (pamh, PAM_OLDAUTHTOK ,(const void**)&old_passwd) != PAM_SUCCESS)
		return FALSE;

	if (pam_get_data (pamh, "login_data", (const void**)&login_data) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get login data [%s]", __FUNCTION__);
		return FALSE;
	}

	if (!login_data || !login_data->login_token) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get login token [%s]", __FUNCTION__);
		return FALSE;
	}

	url = parse_url ();
	if (!url) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get online url [%s]", __FUNCTION__);
		return FALSE;
	}

	ret = request_to_change_password (user, url, login_data->login_token, old_passwd, new_passwd);

	g_free (url);

	return ret;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	gboolean try_first_pass = FALSE;
	int rc = PAM_AUTHTOK_ERR;

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "try_first_pass")) {
			try_first_pass = TRUE;
			break;
		}
	}

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (get_account_type (user) != ACCOUNT_TYPE_GOOROOM)
		return PAM_USER_UNKNOWN;

	if (flags & PAM_PRELIM_CHECK) {
		char *oldpassword = NULL;

		if (try_first_pass) {
			pam_get_item (pamh, PAM_OLDAUTHTOK, (const void**)&oldpassword);
		}

		if (oldpassword == NULL) {
			rc = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &oldpassword, "%s", _("Current password: "));

			if (rc != PAM_SUCCESS) {
				PAM_FORGET (oldpassword);
				return rc;
			}

			rc = verify_current_password (pamh, user, oldpassword);

			if (rc != PAM_SUCCESS) {
				PAM_FORGET (oldpassword);
				return rc;
			}

			pam_set_item (pamh, PAM_OLDAUTHTOK, oldpassword);
			PAM_FORGET (oldpassword);
		}
		return rc;
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		int attempts = 0;
		char *new_password = NULL;
		char *chk_password = NULL;

		if (try_first_pass) {
			pam_get_item (pamh, PAM_AUTHTOK, (const void **)&new_password);
			chk_password = g_strdup (new_password);
		}

		if (!new_password || !chk_password) {
			/* loop, trying to get matching new passwords */
			while (attempts++ < 3) {
				rc = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &new_password, "%s", _("New password: "));
				if (rc != PAM_SUCCESS) {
					goto error;
				}

				rc = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &chk_password, "%s", _("Retype new password: "));
				if (rc != PAM_SUCCESS) {
					goto error;
				}

				/* if they don't match, don't pass them to the next module */
				if (g_strcmp0 (new_password, chk_password) != 0) {
					send_info_msg (pamh, _("Passwords do not match."));
					PAM_FORGET (new_password);
					continue;
				}
				break;
			}
		}

		if (attempts >= 3) { /* too many new password attempts: die */
			rc = PAM_AUTHTOK_ERR;
		} else {
			if (change_online_password (pamh, user, new_password)) {
				pam_set_item (pamh, PAM_AUTHTOK, new_password);
				rc = PAM_SUCCESS;
			} else {
				rc = PAM_AUTHTOK_ERR;
			}
		}

error:
		PAM_FORGET (new_password);
		PAM_FORGET (chk_password);
	}

	return rc;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	const char *user;
	LoginData *login_data = NULL;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	if (get_account_type (user) != ACCOUNT_TYPE_GOOROOM)
		return PAM_USER_UNKNOWN;

	if (pam_get_data (pamh, "login_data", (const void**)&login_data) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get login data [%s]", __FUNCTION__);
		return PAM_USER_UNKNOWN;
	}

	/* temporary password */
	if (login_data->pw_tmp) {
		syslog (LOG_NOTICE, "pam_gooroom : Temporarily issued password for %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "Temporary Password");
		return PAM_NEW_AUTHTOK_REQD;
	}

	/* password already expired */
	if (login_data->pass_exp_remain < 0) {
		syslog (LOG_NOTICE, "pam_gooroom : expired password for user %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "You are required to change your password immediately");
		return PAM_NEW_AUTHTOK_REQD;
	}

	/* password changing cycle expired */
	if (login_data->pw_lastchg == 0) {
		syslog (LOG_NOTICE, "pam_gooroom : expired password for user %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "You are required to change your password immediately");
		return PAM_NEW_AUTHTOK_REQD;
	}

	gint64 leftsec = check_passwd_expiry (pamh, login_data->pw_lastchg, login_data->pw_max);

	if (leftsec <= 0) {
		syslog (LOG_NOTICE, "pam_gooroom : expired password for user %s", user);
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "You are required to change your password immediately");
		return PAM_NEW_AUTHTOK_REQD;
	}

	if (leftsec > 0 && leftsec <= DEFAULT_WARNING_DAYS * DAY_TO_SEC) {
		char *msg = NULL;
		char *res = NULL;

		msg = g_strdup_printf ("Password Maxday Warning:%d", (int)(leftsec / DAY_TO_SEC) + 1);
		retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &res, "%s", msg);
		g_free (msg);

		if (retval != PAM_SUCCESS || g_strcmp0 (res, "chpasswd_yes") != 0) {
			g_free (res);
			goto out;
		}

		g_free (res);

		return PAM_NEW_AUTHTOK_REQD;
	}

out:
	/* Password or Account or Division expiration warning for GPMS user */
	if (login_data->pass_exp_remain <= DEFAULT_WARNING_DAYS ||
        login_data->acct_exp_remain <= DEFAULT_WARNING_DAYS ||
        login_data->dept_exp_remain <= DEFAULT_WARNING_DAYS) {

		char *msg = NULL;
		if (login_data->acct_exp_remain < login_data->dept_exp_remain &&
            login_data->acct_exp_remain < login_data->pass_exp_remain) {
			msg = g_strdup_printf ("Account Expiration Warning:%s:%d",
                                   login_data->acct_exp,
                                   login_data->acct_exp_remain);
		} else if (login_data->dept_exp_remain < login_data->pass_exp_remain) {
			msg = g_strdup_printf ("Division Expiration Warning:%s:%d",
                                   login_data->dept_exp,
                                   login_data->dept_exp_remain);
		} else {
			msg = g_strdup_printf ("Password Expiration Warning:%s:%d",
                                   login_data->pass_exp,
                                   login_data->pass_exp_remain);
		}
		pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, NULL, "%s", msg);
		g_free (msg);
	}

	/* Duplicate login warning for GPMS user */
	if (g_list_length (login_data->dupclients) > 0) {
		char *msg = NULL;
		GList *l = g_list_first (login_data->dupclients);
		DupClient *dupclient = (DupClient *)l->data;

		if (dupclient) {
			msg = g_strdup_printf ("Duplicate Login Notification:%s:%s:%s:%s",
                                   dupclient->client_id, dupclient->client_nm,
                                   dupclient->ip, dupclient->local_ip);
		} else {
			msg = g_strdup ("Duplicate Login Notification");
		}
		pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, NULL, "%s", msg);
		g_free (msg);
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user;
	int account_type, cleanup = 0;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SESSION_ERR;
	}

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "cleanup")) {
			cleanup++;
			break;
		}
	}

	if (cleanup_function_enabled ())
		cleanup++;

	if (cleanup > 0)
		cleanup_users (user);

	account_type = get_account_type (user);

	if (account_type == ACCOUNT_TYPE_LOCAL) {
		delete_config_files (user);
	} else {
		const char *login_raw_data;

		if (pam_get_data (pamh, "login_raw_data", (const void**)&login_raw_data) != PAM_SUCCESS)
			return PAM_SUCCESS;

		struct passwd *user_entry = getpwnam (user);
		if (user_entry) {
			if (make_sure_to_create_save_dir (user_entry->pw_dir)) {
				/* save data to ~/.gooroom/.grm-user */
				save_login_data (user_entry, login_raw_data);
			}
		}
	}

	if (account_type != ACCOUNT_TYPE_GOOROOM)
		restore_pwquality_file ();

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int cleanup = 0;
	const char *user;

	if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		syslog (LOG_ERR, "pam_gooroom: Couldn't get user name [%s]", __FUNCTION__);
		return PAM_SESSION_ERR;
	}

	/* step through arguments */
	for (; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "cleanup")) {
			cleanup++;
			break;
		}
	}

	if (cleanup_function_enabled ())
		cleanup++;

	if (get_account_type (user) == ACCOUNT_TYPE_GOOROOM) {
		char *url = NULL;
		LoginData *login_data = NULL;

		url = parse_url ();
		if (!url) {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to get online url [%s]", __FUNCTION__);
			goto out;
		}

		if (pam_get_data (pamh, "login_data", (const void**)&login_data) != PAM_SUCCESS) {
			g_free (url);
			syslog (LOG_ERR, "pam_gooroom: Error attempting to get login data [%s]", __FUNCTION__);
			goto out;
		}

		if (!logout_from_online (url, login_data->login_token)) {
			syslog (LOG_ERR, "pam_gooroom: Error attempting to logout from online [%s]", __FUNCTION__);
		}

		g_free (url);
	}

out:
	delete_config_files (user);
	restore_pwquality_file ();

	if (cleanup > 0)
		cleanup_users (NULL);

	return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  "pam_gooroom",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_chauthtok,
  pam_sm_open_session,
  pam_sm_close_session
};
#endif
