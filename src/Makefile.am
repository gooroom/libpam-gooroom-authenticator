ACLOCAL_AMFLAGS = -I m4

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_grm_auth.la

pam_grm_auth_la_SOURCES = \
	nfc_auth.c  \
	cleanup.c   \
	common.c    \
	pam.c

pam_grm_auth_la_CFLAGS =	\
	-DLOCALEDIR="\"$(datadir)/locale\""	\
	-DECRYPTFS_WRAP_PASSPHRASE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-wrap-passphrase-helper\""	\
	-DECRYPTFS_WRAP_PASSPHRASE_FILE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-wrap-passphrase-file-helper\""	\
	-DECRYPTFS_REWRAP_PASSPHRASE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-rewrap-passphrase-helper\""	\
	$(AM_CFLAGS)	\
	$(GLIB_CFLAGS)	\
	$(GIO_CFLAGS)	\
	$(CURL_CFLAGS)	\
	$(JSON_C_FLAGS)	\
	$(CRYPTO_CFLAGS)	\
	$(ECRYPTFS_CFLAGS)	\
	$(PCSCLITE_CFLAGS)	\
	$(LIBSSL_CFLAGS)

pam_grm_auth_la_LIBADD =	\
	$(GLIB_LIBS)	\
	$(GIO_LIBS)		\
	$(CURL_LIBS)	\
	$(JSON_C_LIBS)	\
	$(CRYPTO_LIBS)	\
	$(ECRYPTFS_LIBS)	\
	$(PCSCLITE_LIBS)	\
	$(LIBSSL_LIBS)	\
	-lpam

pam_grm_auth_la_LDFLAGS =	\
	$(AM_LDFLAGS)   \
	-module -avoid-version


ecryptfs_wrap_passphrase_helperdir = $(libdir)/gooroom/libpam_gooroom_authenticator
ecryptfs_wrap_passphrase_helper_PROGRAMS = ecryptfs-wrap-passphrase-helper
ecryptfs_wrap_passphrase_helper_SOURCES = ecryptfs-wrap-passphrase-helper.c
ecryptfs_wrap_passphrase_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_wrap_passphrase_helper_LDFLAGS = $(ECRYPTFS_LIBS)

ecryptfs_rewrap_passphrase_helperdir = $(libdir)/gooroom/libpam_gooroom_authenticator
ecryptfs_rewrap_passphrase_helper_PROGRAMS = ecryptfs-rewrap-passphrase-helper
ecryptfs_rewrap_passphrase_helper_SOURCES = ecryptfs-rewrap-passphrase-helper.c
ecryptfs_rewrap_passphrase_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_rewrap_passphrase_helper_LDFLAGS = $(ECRYPTFS_LIBS)

ecryptfs_wrap_passphrase_file_helperdir = $(libdir)/gooroom/libpam_gooroom_authenticator
ecryptfs_wrap_passphrase_file_helper_PROGRAMS = ecryptfs-wrap-passphrase-file-helper
ecryptfs_wrap_passphrase_file_helper_SOURCES = ecryptfs-wrap-passphrase-file-helper.c
ecryptfs_wrap_passphrase_file_helper_CFLAGS = $(ECRYPTFS_CFLAGS)
ecryptfs_wrap_passphrase_file_helper_LDFLAGS = $(ECRYPTFS_LIBS)

install-exec-hook:
	rm -f $(DESTDIR)$(PAMDIR)/*.a 
	rm -f $(DESTDIR)$(PAMDIR)/*.la
