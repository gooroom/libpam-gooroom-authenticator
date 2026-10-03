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

#include <pwd.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "common.h"


static gchar *user = NULL;
static gchar *password = NULL;
static gchar *user_prefix = NULL;
static gchar *password_type = NULL;

static GOptionEntry option_entries[] =
{
	{ "user",        'u', 0, G_OPTION_ARG_STRING, &user,     NULL, NULL },
	{ "user-prefix", 'p', 0, G_OPTION_ARG_STRING, &user_prefix, NULL, NULL },
	{ "password_type", 'p', 0, G_OPTION_ARG_STRING, &password_type, NULL, NULL },
	{ NULL }
};



/* curl -d "user_id=xxxxxxx&user_pw=xxxxxxxxxx"
 * -X POST "https://demo-glm12.gooroom.kr/glm/v1/pam/authconfirm"
 * --cert "/etc/ssl/certs/gooroom_client.crt" --key "/etc/ssl/private/gooroom_client.key"
*/
static void
do_authentication (const char *user, const char *password, const char *user_prefix, const gchar *password_type)
{
	char *pw_hash = NULL;
	char *url = parse_url ();

	if (user_prefix) {
		/* remove prefix from user */
		if (strstr (user, user_prefix) != NULL) {
	        char *id = strstr (user, user_prefix) + strlen (user_prefix);
			pw_hash = create_hash (id, password, password_type, NULL);
		} else {
			pw_hash = create_hash (user, password, password_type, NULL);
		}
	} else {
		pw_hash = create_hash (user, password, password_type, NULL);
	}

	/* This program is setuid root and holds the client key: run curl with an
	 * argv (no shell), -q (ignore any curlrc) and the form body on stdin so the
	 * password hash never appears on a command line. */
	g_autofree gchar *endpoint = g_strdup_printf ("https://%s/glm/v1/pam/authconfirm", url ? url : "");
	g_autofree gchar *uid_enc = g_uri_escape_string (user, NULL, FALSE);
	g_autofree gchar *body = g_strdup_printf ("user_id=%s&user_pw=%s", uid_enc, pw_hash ? pw_hash : "");
	gchar *argv[] = { "/usr/bin/curl", "-q", "-s", "--data-binary", "@-", "-X", "POST", endpoint,
	                  "--cert", GOOROOM_CERT, "--key", GOOROOM_PRIVATE_KEY, NULL };
	GPid pid;
	gint in_fd = -1;

	if (url && g_spawn_async_with_pipes (NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	                                     &pid, &in_fd, NULL, NULL, NULL)) {
		gsize len = strlen (body), off = 0;
		while (off < len) {
			ssize_t n = write (in_fd, body + off, len - off);
			if (n <= 0) break;
			off += n;
		}
		close (in_fd);
		waitpid (pid, NULL, 0);
		g_spawn_close_pid (pid);
	}

	memset (body, 0, strlen (body));
	g_free (url);
	g_free (pw_hash);
}

/* The password is read from stdin, never argv (argv is visible to every local user). */
static gchar *
read_password (void)
{
	char buf[4096];

	if (!fgets (buf, sizeof (buf), stdin))
		return NULL;
	buf[strcspn (buf, "\n")] = '\0';
	gchar *ret = g_strdup (buf);
	memset (buf, 0, sizeof (buf));
	return ret;
}

static gboolean
is_valid_username (const char *user)
{
	struct passwd pw, *pwp;
	char buf[4096] = {0,};

	getpwnam_r (user, &pw, buf, sizeof (buf), &pwp);

	return (pwp != NULL);
}

int
main (int argc, char **argv)
{
	gboolean        retval;
	GError         *error = NULL;
	GOptionContext *context;

	/* setuid root: drop everything the caller put in the environment */
	clearenv ();
	setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

	context = g_option_context_new (NULL);
	g_option_context_add_main_entries (context, option_entries, NULL);
	retval = g_option_context_parse (context, &argc, &argv, &error);
	g_option_context_free (context);

	/* parse options */
	if (!retval) {
		g_warning ("%s", error->message);
		g_error_free (error);
		return EXIT_FAILURE;
	}

	password = read_password ();
	if (!user || !password) {
		g_warning ("No user or password was specified.");
		return EXIT_FAILURE;
	}

	if (!is_valid_username (user)) {
		g_warning ("Invalid username.");
		return EXIT_FAILURE;
	}

	/* A non-root caller may only check its own password. */
	if (getuid () != 0) {
		struct passwd *self = getpwuid (getuid ());
		if (!self || g_strcmp0 (self->pw_name, user) != 0) {
			g_warning ("Permission denied.");
			return EXIT_FAILURE;
		}
	}

	do_authentication (user, password, user_prefix, password_type);

	return EXIT_SUCCESS;
}
