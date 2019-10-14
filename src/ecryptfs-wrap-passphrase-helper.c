/**
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *            Dustin Kirkland <kirkland@ubuntu.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ecryptfs.h>



int
main (int argc, char **argv)
{
	char *file;
	char *passphrase = NULL;
	char *wrapping_passphrase = NULL;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 1;

	if (argc != 4) {
		goto out;
	}

	file = argv[1];
	passphrase = argv[2];
	wrapping_passphrase = argv[3];

	if (passphrase == NULL || wrapping_passphrase == NULL ||
	    strlen (passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH ||
	    strlen (wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		goto out;
	}

	rc = ecryptfs_read_salt_hex_from_rc (salt_hex);
	if (rc) {
		from_hex (salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else {
		from_hex (salt, salt_hex, ECRYPTFS_SALT_SIZE);
	}

	if ((rc = ecryptfs_wrap_passphrase (file, wrapping_passphrase, salt, passphrase)) != 0)
		rc = 1;

out:
	return rc;
}
