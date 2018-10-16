pammod_PROGRAMS=pam_grm_auth.so
pammoddir=$(PAMDIR)

pam_grm_auth_so_SOURCES = common.c pam.c nfc_auth.c custom-hash-helper.h
pam_grm_auth_so_CFLAGS = -fPIC -Wall $(GLIB_CFLAGS) $(CURL_CFLAGS) $(JSON_C_FLAGS) $(CRYPTO_CFLAGS) $(ECRYPTFS_CFLAGS) $(PCSCLITE_CFLAGS) $(LIBSSL_CFLAGS) -DLOCALEDIR="\"$(datadir)/locale\"" -DECRYPTFS_WRAP_PASSPHRASE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-wrap-passphrase-helper\"" -DECRYPTFS_WRAP_PASSPHRASE_FILE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-wrap-passphrase-file-helper\"" -DECRYPTFS_REWRAP_PASSPHRASE_HELPER="\"$(libdir)/gooroom/libpam_gooroom_authenticator/ecryptfs-rewrap-passphrase-helper\""
pam_grm_auth_so_LDFLAGS = -shared
pam_grm_auth_so_LDADD = $(PAM_LIBS) $(GLIB_LIBS) $(CURL_LIBS) $(JSON_C_LIBS) $(CRYPTO_LIBS) $(ECRYPTFS_LIBS) $(PCSCLITE_LIBS) $(LIBSSL_LIBS)


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
