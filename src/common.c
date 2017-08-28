/*
 * Copyright (C) 2015-2017 Gooroom <gooroom@gooroom.kr>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <config.h>

#include <glib.h>

#include <security/pam_modules.h>

#include "common.h"


gboolean
pam_msg (pam_handle_t *pamh, const char *msg)
{
	const struct pam_message pam_msg = {
		.msg_style = PAM_TEXT_INFO,
		.msg = msg,
	};

	const struct pam_message *msgp = &pam_msg;
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
