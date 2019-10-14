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

#ifndef __PWQUALITY_CONF_TEMPLATE_H__
#define	__PWQUALITY_CONF_TEMPLATE_H__

#include <stdio.h>

const char *pwquality_conf_data = ""
"# Configuration for systemwide password quality limits\n"
"# Defaults:\n"
"#\n"
"# Number of characters in the new password that must not be present in the\n"
"# old password.\n"
" difok = %s\n"
"#\n"
"# Minimum acceptable size for the new password (plus one if\n"
"# credits are not disabled which is the default). (See pam_cracklib manual.)\n"
"# Cannot be set to lower value than 6.\n"
" minlen = %s\n"
"#\n"
"# The maximum credit for having digits in the new password. If less than 0\n"
"# it is the minimum number of digits in the new password.\n"
" dcredit = %s\n"
"#\n"
"# The maximum credit for having uppercase characters in the new password.\n"
"# If less than 0 it is the minimum number of uppercase characters in the new\n"
"# password.\n"
" ucredit = %s\n"
"#\n"
"# The maximum credit for having lowercase characters in the new password.\n"
"# If less than 0 it is the minimum number of lowercase characters in the new\n"
"# password.\n"
" lcredit = %s\n"
"#\n"
"# The maximum credit for having other characters in the new password.\n"
"# If less than 0 it is the minimum number of other characters in the new\n"
"# password.\n"
" ocredit = %s\n"
"#\n"
"# The minimum number of required classes of characters for the new\n"
"# password (digits, uppercase, lowercase, others).\n"
" minclass = %s\n"
"#\n"
"# The maximum number of allowed consecutive same characters in the new password.\n"
"# The check is disabled if the value is 0.\n"
"# maxrepeat = 0\n"
"#\n"
"# The maximum number of allowed consecutive characters of the same class in the\n"
"# new password.\n"
"# The check is disabled if the value is 0.\n"
"# maxclassrepeat = 0\n"
"#\n"
"# Whether to check for the words from the passwd entry GECOS string of the user.\n"
"# The check is enabled if the value is not 0.\n"
"# gecoscheck = 0\n"
"#\n"
"# Whether to check for the words from the cracklib dictionary.\n"
"# The check is enabled if the value is not 0.\n"
"# dictcheck = 1\n"
"#\n"
"# Whether to check if it contains the user name in some form.\n"
"# The check is enabled if the value is not 0.\n"
"# usercheck = 1\n"
"#\n"
"# Whether the check is enforced by the PAM module and possibly other\n"
"# applications.\n"
"# The new password is rejected if it fails the check and the value is not 0.\n"
"# enforcing = 1\n"
"#\n"
"# Path to the cracklib dictionaries. Default is to use the cracklib default.\n"
"# dictpath =\n";

#endif
