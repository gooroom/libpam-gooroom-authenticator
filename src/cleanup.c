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
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include "common.h"
#include "cleanup.h"


#define ETC_PASSWD           "/etc/passwd"
#define PROC_SELF_LOGINUID   "/proc/self/loginuid"
#define PROC_SELF_MOUNTS     "/proc/self/mounts"
#define USERDEL_COMMAND      "/usr/sbin/userdel"
#define FUSER_COMMAND        "/bin/fuser"
#define PKILL_COMMAND        "/usr/bin/pkill"
#define ECRYPTFS_DIR         "/home/.ecryptfs"
#define AGENT_CONF           "/etc/gooroom/agent/Agent.conf"



/*
 * Copied from nautilus-3.30.5/src/nautilus-file-operations.c:
 * delete_file_recursively ()
 */
static gboolean
delete_file_recursively (GFile *file)
{
	gboolean success;
	g_autoptr (GError) error = NULL;

	do {
		g_autoptr (GFileEnumerator) enumerator = NULL;

		success = g_file_delete (file, NULL, &error);
		if (success || !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_EMPTY)) {
			if (!success) {
				syslog (LOG_ERR, "pam_gooroom: Error attempting to delete ecryptfs directory: [%s]", error->message);
			}
			break;
		}

		g_clear_error (&error);

		enumerator = g_file_enumerate_children (file,
				G_FILE_ATTRIBUTE_STANDARD_NAME,
				G_FILE_QUERY_INFO_NONE,
				NULL, &error);

		if (enumerator) {
			GFileInfo *info;

			success = TRUE;

			info = g_file_enumerator_next_file (enumerator, NULL, &error);

			while (info != NULL) {
				GFile *child = NULL;

				child = g_file_enumerator_get_child (enumerator, info);

				success = success && delete_file_recursively (child);

				g_object_unref (child);
				g_object_unref (info);

				info = g_file_enumerator_next_file (enumerator, NULL, &error);
			}

			g_object_unref (enumerator);
		}

		if (error != NULL)
			success = FALSE;
	} while (success);

	return success;
}

static GList *
get_all_mount_dirs (void)
{
	char *contents = NULL;
	GList *dirs = NULL;

	g_file_get_contents (PROC_SELF_MOUNTS, &contents, NULL, NULL);
	if (contents) {
		guint i = 0;
		char **lines = g_strsplit (contents, "\n", -1);
		for (i = 0; i < g_strv_length (lines); i++) {
			char **columns = g_strsplit (lines[i], " ", -1);
			if (g_strv_length (columns) >= 3) {
				dirs = g_list_append (dirs, g_strdup (columns[1]));
				syslog (LOG_INFO, "pam_gooroom: Current Mount Dir: [%s]", columns[1]);
			}
			g_strfreev (columns);
		}
		g_strfreev (lines);
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to get contents of %s", PROC_SELF_MOUNTS);
	}

	return dirs;
}

//static gboolean
//is_user_logged_in (uid_t uid)
//{
//	gboolean ret = FALSE;
//	char *contents = NULL;
//
//	g_file_get_contents (PROC_SELF_LOGINUID, &contents, NULL, NULL);
//	if (contents) {
//		gchar *str_uid = g_strdup_printf ("%d", uid);
//		if (g_str_equal (contents, str_uid))
//			ret = TRUE;
//		g_free (str_uid);
//	}
//
//	return ret;
//}

static gboolean
unmount_dirs (const char *homedir, GList *mount_dirs)
{
	GList *l = NULL;
	GError *error = NULL;
	gboolean ret = TRUE;

	for (l = mount_dirs; l; l = l->next) {
		char *mnt_dir = (char *)l->data;
		if (g_str_equal (mnt_dir, homedir) || strstr (mnt_dir, homedir) != NULL) {
			char *cmd = g_strdup_printf ("%s -ck %s", FUSER_COMMAND, mnt_dir);

			if (!g_spawn_command_line_sync (cmd, NULL, NULL, NULL, &error)) {
				syslog (LOG_ERR, "pam_gooroom: Error attempting to unmount %s directory: [%s]", mnt_dir, error->message);
				g_error_free (error);
				ret = FALSE;
			}
			g_free (cmd);
		}
	}

	return ret;
}

static gboolean
kill_user_process (const char *deluser)
{
	char *cmd = NULL;
	GError *error = NULL;
	gboolean ret = FALSE;

	cmd = g_strdup_printf ("%s -u %s", PKILL_COMMAND, deluser);

	if (g_spawn_command_line_sync (cmd, NULL, NULL, NULL, &error)) {
		ret = TRUE;
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to kill %s's process : [%s]", deluser, error->message);
		g_error_free (error);
		ret = FALSE;
	}

	return ret;
}

static gboolean
delete_account (const char *deluser)
{
	char *cmd = NULL;
	GError *error = NULL;
	gboolean ret = FALSE;

	cmd = g_strdup_printf ("%s -rf %s", USERDEL_COMMAND, deluser);

	if (g_spawn_command_line_sync (cmd, NULL, NULL, NULL, &error)) {
		ret = TRUE;
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to delete %s account: [%s]", deluser, error->message);
		g_error_free (error);
		ret = FALSE;
	}

	g_free (cmd);

	return ret;
}

static gboolean
remove_ecryptfs (const char *deluser)
{
	gboolean ret = TRUE;
	GError *error = NULL;
	char *ecryptfs_dir = NULL;

	ecryptfs_dir = g_build_filename (ECRYPTFS_DIR, deluser, NULL);
	if (g_file_test (ecryptfs_dir, G_FILE_TEST_EXISTS) &&
        (!g_str_equal (ecryptfs_dir, ECRYPTFS_DIR)))
	{
		GFile *file = g_file_new_for_path (ecryptfs_dir);
		ret = delete_file_recursively (file);
		g_object_unref (file);

//		#define RM_COMMAND           "/bin/rm"
//		char *cmd = g_strdup_printf ("%s -rf %s", RM_COMMAND, ecryptfs_dir);
//		if (!g_spawn_command_line_sync (cmd, NULL, NULL, NULL, &error)) {
//			syslog (LOG_ERR, "pam_gooroom: Error attempting to delete %s account: [%s]", deluser, error->message);
//			g_error_free (error);
//			ret = FALSE;
//		}
//
//		g_free (cmd);
	}

	g_free (ecryptfs_dir);

	return ret;
}

static void
cleanup_account (const char *deluser,
                 const char *except_user,
                 GList      *mount_dirs)
{
	struct passwd *entry = getpwnam (deluser);
	if (entry) {
//		if (is_user_logged_in (entry->pw_uid))
//			return;

		if (except_user && g_str_equal (deluser, except_user))
			return;

		kill_user_process (deluser);

		if (unmount_dirs (entry->pw_dir, mount_dirs)) {
			if (remove_ecryptfs (deluser)) {
				delete_account (deluser);
			}
		}
	}
}

void
cleanup_users (const char *except_user)
{
	char *contents = NULL;
	GList *mount_dirs = NULL;

	mount_dirs = get_all_mount_dirs ();

	g_file_get_contents (ETC_PASSWD, &contents, NULL, NULL);
	if (contents) {
		guint i = 0;
		char **lines = g_strsplit (contents, "\n", -1);
		for (i = 0; i < g_strv_length (lines); i++) {
			if (g_str_has_prefix (lines[i], "root") ||
                g_str_has_suffix (lines[i], "/bin/false") ||
                g_str_has_suffix (lines[i], "/bin/sync") ||
                g_str_has_suffix (lines[i], "/usr/sbin/nologin")) {
				continue;
			}
			char **columns = g_strsplit (lines[i], ":", -1);
			if (g_strv_length (columns) > 4) {
				if (g_strcmp0 (columns[4], "") == 0) {
					continue;
				}
				char **items = g_strsplit (columns[4], ",", -1);
				if (g_strv_length (items) > 4) {
					if (g_str_equal (items[4], GOOROOM_ACCOUNT) ||
                        g_str_equal (items[4], GOOGLE_ACCOUNT) ||
                        g_str_equal (items[4], NAVER_ACCOUNT)) {
						cleanup_account (columns[0], except_user, mount_dirs);
					}
				}
				g_strfreev (items);
			}
			g_strfreev (columns);
		}
		g_strfreev (lines);
	}

	g_free (contents);

	g_list_free_full (mount_dirs, g_free);
}

gboolean
cleanup_function_enabled (void)
{
	GError   *error    = NULL;
	GKeyFile *keyfile  = NULL;
	gboolean  ret      = FALSE;

	keyfile = g_key_file_new ();

	g_key_file_load_from_file (keyfile, AGENT_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "CLIENTJOB")) {
			char *enable = g_key_file_get_string (keyfile, "CLIENTJOB", "HOMEFOLDER_OPERATION", NULL);
			ret = g_str_equal (enable, "enable");
			g_free (enable);
		}
	} else {
		syslog (LOG_ERR, "pam_gooroom: Error attempting to load %s: [%s]", AGENT_CONF, error->message);
		g_clear_error (&error);
	}

	g_key_file_free (keyfile);

	return ret;
}

void
cleanup_cookies (const char *user)
{
	struct passwd *entry = getpwnam (user);

	if (entry) {
		char *filename = g_build_filename (entry->pw_dir,
                                           ".config/chromium/Default/Cookies", NULL);

		if (g_file_test (filename, G_FILE_TEST_EXISTS)) {
			if (g_remove (filename) == -1) {
				syslog (LOG_INFO, "pam_gooroom: Error attempting to clean up user credential [%s]", __FUNCTION__);
			}
		}

		g_free (filename);
	}
}
