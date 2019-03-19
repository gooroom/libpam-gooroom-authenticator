AC_INIT([libpam-gooroom-authenticator], [0.1.0])
AC_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([no-dist-gzip dist-xz foreign])

AM_GNU_GETTEXT([external])

ALL_LINGUAS="en_US ko"

AC_PREREQ([2.59])
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

AC_SUBST(PAMDIR, "\$(exec_prefix)/lib/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

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
