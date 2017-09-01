pammod_PROGRAMS=pam_grm_auth.so
pammoddir=$(PAMDIR)

pam_grm_auth_so_SOURCES = common.c pam.c nfc_auth.c
pam_grm_auth_so_CFLAGS = -fPIC -Wall $(GLIB_CFLAGS) $(CURL_CFLAGS) $(JSON_C_FLAGS) $(CRYPTO_CFLAGS) $(PCSCLITE_CFLAGS) -DLOCALEDIR="\"$(datadir)/locale\""
pam_grm_auth_so_LDFLAGS = -shared
pam_grm_auth_so_LDADD = $(PAM_LIBS) $(GLIB_LIBS) $(CURL_LIBS) $(JSON_C_LIBS) $(CRYPTO_LIBS) $(PCSCLITE_LIBS)
