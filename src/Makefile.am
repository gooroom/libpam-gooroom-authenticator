pammod_PROGRAMS = pam_grm_auth.so
pammoddir=$(PAMDIR)

pam_grm_auth_so_SOURCES = pam.c
pam_grm_auth_so_CFLAGS = -fpic -Wall $(GLIB_CFLAGS) $(CURL_CFLAGS) $(JSON_C_FLAGS)
pam_grm_auth_so_LDFLAGS = -shared
pam_grm_auth_so_LDADD = $(PAM_LIBS) $(GLIB_LIBS) $(CURL_LIBS) $(JSON_C_LIBS)
