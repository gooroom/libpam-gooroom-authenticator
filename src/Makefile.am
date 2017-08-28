pammod_LTLIBRARIES= pam_grm_auth.la
pammoddir=$(PAMDIR)

pam_grm_auth_la_SOURCES = common.c pam.c nfc_auth.c
pam_grm_auth_la_CFLAGS = -fPIC -Wall $(GLIB_CFLAGS) $(CURL_CFLAGS) $(JSON_C_FLAGS) $(CRYPTO_CFLAGS) $(PCSCLITE_CFLAGS) -DLOCALEDIR="\"$(datadir)/locale\""
pam_grm_auth_la_LDFLAGS = -avoid-version -module -Wl,-z,nodelete
pam_grm_auth_la_LIBADD = $(PAM_LIBS) $(GLIB_LIBS) $(CURL_LIBS) $(JSON_C_LIBS) $(CRYPTO_LIBS) $(PCSCLITE_LIBS)
