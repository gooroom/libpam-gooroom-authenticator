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


#include "pam-common.h"


/* Copied from fprintd/pam/pam_fprintd.c:
 * send_info_msg () */
gboolean
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

/* Copied from pam-radius/pam_radius_auth.c:
 * rad_converse () */
int
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
