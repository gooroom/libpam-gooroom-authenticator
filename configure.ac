AC_INIT([pam-gooroom], [0.2.3])
AC_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

AM_GNU_GETTEXT([external])

ALL_LINGUAS="en_US ko"

AC_PREREQ([2.63])
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_ARG_WITH(
	[pamdir],
	[AS_HELP_STRING([--with-pamdir=PATH],[Specify the directory where PAM modules are stored])],
	[pamdir="${withval}"],
	[
		if test "${prefix}" = "/usr"; then
			pamdir="/lib${libdir##*/lib}/security"
		else
			pamdir="\$(libdir)/security"
		fi
	]
)
AC_SUBST([pamdir])

PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([GIO], [gio-2.0])
PKG_CHECK_MODULES([CURL], [libcurl])
PKG_CHECK_MODULES([JSON_C], [json-c])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
PKG_CHECK_MODULES([ECRYPTFS], [libecryptfs])
PKG_CHECK_MODULES([LIBSSL], [libssl])
PKG_CHECK_MODULES([PCSCLITE], [libpcsclite])

AC_CONFIG_FILES([
	Makefile
	po/Makefile.in
	src/Makefile
])
AC_OUTPUT
