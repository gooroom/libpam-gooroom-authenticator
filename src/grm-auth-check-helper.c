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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "common.h"


static gchar *user = NULL;
static gchar *password = NULL;
static gchar *user_prefix = NULL;

static GOptionEntry option_entries[] =
{
	{ "user",        'u', 0, G_OPTION_ARG_STRING, &user,     NULL, NULL },
	{ "password",    'p', 0, G_OPTION_ARG_STRING, &password, NULL, NULL },
	{ "user-prefix", 'p', 0, G_OPTION_ARG_STRING, &user_prefix, NULL, NULL },
	{ NULL }
};



/* curl -d "user_id=xxxxxxx&user_pw=xxxxxxxxxx"
 * -X POST "https://demo-glm12.gooroom.kr/glm/v1/pam/authconfirm"
 * --cert "/etc/ssl/certs/gooroom_client.crt" --key "/etc/ssl/private/gooroom_client.key"
*/
static void
do_authentication (const char *user, const char *password, const char *user_prefix)
{
	char *pw_hash = NULL;
	char *url = parse_url ();

	if (user_prefix) {
		/* remove prefix from user */
        char *id = strstr (user, user_prefix) + strlen (user_prefix);
		pw_hash = create_hash (id, password, NULL);
	} else {
		pw_hash = create_hash (user, password, NULL);
	}

	char *cmd = g_strdup_printf ("/usr/bin/curl -d"
                                 " \"user_id=%s&user_pw=%s\""
                                 " -X POST \"https://%s/glm/v1/pam/authconfirm\""
                                 " --cert \"%s\""
                                 " --key \"%s\"",
                                 user,
                                 pw_hash,
                                 url,
                                 GOOROOM_CERT,
                                 GOOROOM_PRIVATE_KEY);

	g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL);

	g_free (url);
	g_free (pw_hash);
	g_free (cmd);
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

	if (!user || !password) {
		g_warning ("No user or password was specified.");
		return EXIT_FAILURE;
	}

	if (!is_valid_username (user)) {
		g_warning ("Invalid username.");
		return EXIT_FAILURE;
	}

	do_authentication (user, password, user_prefix);

	return EXIT_SUCCESS;
}
