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

#ifndef _NFC_AUTH_H_
#define _NFC_AUTH_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <security/pam_modules.h>

#include <glib.h>

G_BEGIN_DECLS

gboolean	nfc_data_get	(pam_handle_t *pamh, char **data);

G_END_DECLS

#endif /* _NFC_AUTH_H_ */
