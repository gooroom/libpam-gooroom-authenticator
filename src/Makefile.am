ACLOCAL_AMFLAGS = -I m4

pam_LTLIBRARIES = pam_gooroom.la

pkglibexec_PROGRAMS = \
	grm-auth-check-helper \
	ecryptfs-wrap-passphrase-helper \
	ecryptfs-wrap-passphrase-file-helper \
	ecryptfs-rewrap-passphrase-helper

pam_gooroom_la_SOURCES = \
	nfc-auth.c	\
	cleanup.c	\
	pam-common.c	\
	common.c	\
	pam.c	\
	jwt.c

pam_gooroom_la_LIBADD =	\
	$(GLIB_LIBS)	\
	$(GIO_LIBS)	\
	$(CURL_LIBS)	\
	$(JSON_C_LIBS)	\
	$(CRYPTO_LIBS)	\
	$(ECRYPTFS_LIBS)	\
	$(PCSCLITE_LIBS)	\
	$(LIBSSL_LIBS)	\
	-lpam	\
	-lb64

pam_gooroom_la_CFLAGS = \
	-DLOCALEDIR=\"$(localedir)\"	\
	-DGRM_AUTH_CHECK_HELPER=\"$(pkglibexecdir)/grm-auth-check-helper\"	\
	-DECRYPTFS_WRAP_PASSPHRASE_HELPER=\"$(pkglibexecdir)/ecryptfs-wrap-passphrase-helper\"	\
	-DECRYPTFS_WRAP_PASSPHRASE_FILE_HELPER=\"$(pkglibexecdir)/ecryptfs-wrap-passphrase-file-helper\"	\
	-DECRYPTFS_REWRAP_PASSPHRASE_HELPER=\"$(pkglibexecdir)/ecryptfs-rewrap-passphrase-helper\"	\
	$(AM_CFLAGS)	\
	$(GLIB_CFLAGS)	\
	$(GIO_CFLAGS)	\
	$(CURL_CFLAGS)	\
	$(JSON_C_FLAGS)	\
	$(CRYPTO_CFLAGS)	\
	$(ECRYPTFS_CFLAGS)	\
	$(PCSCLITE_CFLAGS)	\
	$(LIBSSL_CFLAGS)

pam_gooroom_la_LDFLAGS =	\
	$(AM_LDFLAGS)	\
	-module -avoid-version

grm_auth_check_helper_SOURCES = \
	grm-auth-check-helper.c \
	common.c

grm_auth_check_helper_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBSSL_CFLAGS) \
	$(CRYPTO_CFLAGS)

grm_auth_check_helper_LDFLAGS = \
	$(GLIB_LIBS) \
	$(LIBSSL_LIBS) \
	$(CRYPTO_LIBS)

ecryptfs_wrap_passphrase_helper_SOURCES = ecryptfs-wrap-passphrase-helper.c
ecryptfs_wrap_passphrase_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_wrap_passphrase_helper_LDFLAGS = $(ECRYPTFS_LIBS)

ecryptfs_rewrap_passphrase_helper_SOURCES = ecryptfs-rewrap-passphrase-helper.c
ecryptfs_rewrap_passphrase_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_rewrap_passphrase_helper_LDFLAGS = $(ECRYPTFS_LIBS)

ecryptfs_wrap_passphrase_file_helper_SOURCES = ecryptfs-wrap-passphrase-file-helper.c
ecryptfs_wrap_passphrase_file_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_wrap_passphrase_file_helper_LDFLAGS = $(ECRYPTFS_LIBS)

install-exec-hook:
	rm -f "$(DESTDIR)$(pamdir)/*.a"
	rm -f "$(DESTDIR)$(pamdir)/*.la"
	chown root "$(DESTDIR)$(pkglibexecdir)/grm-auth-check-helper"
	chmod +s "$(DESTDIR)$(pkglibexecdir)/grm-auth-check-helper"

uninstall-local:
	rm -f "$(DESTDIR)$(pamdir)/pam_gooroom.so"
