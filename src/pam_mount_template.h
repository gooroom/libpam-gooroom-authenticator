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

#ifndef __PAM_MOUNT_TEMPLATE_H_
#define	__PAM_MOUNT_TEMPLATE_H_

#include <stdio.h>


const char *pam_mount_volume_definitions = "<volume fstype=\"davfs\" path=\"%s\" mountpoint=\"/home/%%(USER)/%s\" options=\"username=%%(USER),nosuid,nodev,uid=%%(USER)\" />";

const char *pam_mount_xml_template_prefix = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
"<!DOCTYPE pam_mount SYSTEM \"pam_mount.conf.xml.dtd\">\n"
"<!--\n"
"    See pam_mount.conf(5) for a description.\n"
"-->\n"
"\n"
"<pam_mount>\n"
"\n"
"        <!-- debug should come before everything else,\n"
"        since this file is still processed in a single pass\n"
"        from top-to-bottom -->\n"
"\n"
"<debug enable=\"0\" />\n"
"\n"
"        <!-- Volume definitions -->\n"
"\n";

const char *pam_mount_xml_template_suffix = "\n"
"        <!-- pam_mount parameters: General tunables -->\n"
"\n"
"<!--\n"
"<luserconf name=\".pam_mount.conf.xml\" />\n"
"-->\n"
"\n"
"<!-- Note that commenting out mntoptions will give you the defaults.\n"
"     You will need to explicitly initialize it with the empty string\n"
"     to reset the defaults to nothing. -->\n"
"<mntoptions allow=\"nosuid,nodev,loop,encryption,fsck,nonempty,allow_root,allow_other\" />\n"
"<!--\n"
"<mntoptions deny=\"suid,dev\" />\n"
"<mntoptions allow=\"*\" />\n"
"<mntoptions deny=\"*\" />\n"
"-->\n"
"<mntoptions require=\"nosuid,nodev\" />\n"
"\n"
"<logout wait=\"0\" hup=\"0\" term=\"0\" kill=\"0\" />\n"
"\n"
"\n"
"        <!-- pam_mount parameters: Volume-related -->\n"
"\n"
"<mkmountpoint enable=\"1\" remove=\"true\" />\n"
"\n"
"\n"
"</pam_mount>";

#endif
