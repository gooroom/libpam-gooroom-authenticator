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
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "common.h"


static gchar *user = NULL;
static gchar *password = NULL;

static GOptionEntry option_entries[] =
{
	{ "user",     'u', 0, G_OPTION_ARG_STRING, &user,     NULL, NULL },
    { "password", 'p', 0, G_OPTION_ARG_STRING, &password, NULL, NULL },
    { NULL }
};



/* curl -d "user_id=xxxxxxx&user_pw=xxxxxxxxxx"
 * -X POST "https://demo-glm12.gooroom.kr/glm/v1/pam/authconfirm"
 * --cert "/etc/ssl/certs/gooroom_client.crt" --key "/etc/ssl/private/gooroom_client.key"
*/
static void
do_authentication (const char *user, const char *password)
{
	char *url = parse_url ();
	char *pw_hash = create_hash (user, password, NULL);

	char *cmd = g_strdup_printf ("curl -d"
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

int
main (int argc, char **argv)
{
	GError         *error = NULL;
	GOptionContext *context;

	context = g_option_context_new (NULL);
	g_option_context_set_ignore_unknown_options (context, TRUE);
	g_option_context_add_main_entries (context, option_entries, NULL);

	/* parse options */
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_error_free (error);
		g_option_context_free (context);

		return EXIT_FAILURE;
	}
	g_option_context_free (context);

	if (!user || !password)
		return EXIT_FAILURE;

	do_authentication (user, password);

	return EXIT_SUCCESS;
}
