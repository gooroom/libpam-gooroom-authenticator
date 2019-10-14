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


#ifndef _PAM_COMMON_H_
#define _PAM_COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <security/pam_modules.h>


G_BEGIN_DECLS

gboolean send_info_msg (pam_handle_t *pamh,
                        const char   *msg);

int      rad_converse (pam_handle_t  *pamh,
                       int            msg_style,
                       char          *message,
                       char         **password);

G_END_DECLS

#endif
