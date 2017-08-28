/*
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2008 Bastien Nocera <hadess@hadess.net>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <config.h>

#include <glib.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <winscard.h>

#include "common.h"
#include "nfc_auth.h"


#ifndef SCARD_E_NO_READERS_AVAILABLE
#define SCARD_E_NO_READERS_AVAILABLE 0x8010002E
#endif

#define TIMEOUT 10000 /* 10 seconds */


static gboolean
send_apdu (SCARDCONTEXT context,
           LPTSTR reader_name,
           unsigned char *send_buffer,
           DWORD send_length,
           unsigned char *recv_buffer,
           DWORD *recv_length)
{
	LONG rv;
	DWORD dwPref;
	SCARDHANDLE h_card;
	gboolean ret = TRUE;;

	rv = SCardConnect (context, reader_name,
			SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &h_card, &dwPref);

	if (rv == SCARD_S_SUCCESS) {
		rv = SCardTransmit (h_card, SCARD_PCI_T1, send_buffer, send_length, NULL, recv_buffer, recv_length);
		if (rv != SCARD_S_SUCCESS) {
			ret = FALSE;
		}

		(void)SCardDisconnect (h_card, SCARD_LEAVE_CARD);
	} else {
		ret = FALSE;
	}

	return ret;
}

static gboolean
authenticate (SCARDCONTEXT context, LPTSTR reader_name)
{
	DWORD recv_length;
	unsigned char send_buffer[32] = {0, };
	unsigned char recv_buffer[32] = {0, };

	recv_length = sizeof (recv_buffer);
	memset (send_buffer, 0x00, sizeof (send_buffer));
	memset (recv_buffer, 0x00, sizeof (recv_buffer));
	memcpy (send_buffer, "\xFF\xCA\x00\x00\x00", 5);

	if (!send_apdu (context, reader_name, send_buffer, 5, recv_buffer, &recv_length))
		return FALSE;

	recv_length = sizeof (recv_buffer);
	memset (send_buffer, 0x00, sizeof (send_buffer));
	memset (recv_buffer, 0x00, sizeof (recv_buffer));
	memcpy (send_buffer, "\xFF\x82\x00\x00\x06\xFF\xFF\xFF\xFF\xFF\xFF", 11);

	if (!send_apdu (context, reader_name, send_buffer, 11, recv_buffer, &recv_length))
		return FALSE;

	recv_length = sizeof (recv_buffer);
	memset (send_buffer, 0x00, sizeof (send_buffer));
	memset (recv_buffer, 0x00, sizeof (recv_buffer));
	memcpy (send_buffer, "\xFF\x86\x00\x00\x05\x01\x00\x1F\x60\x00", 10);

	if (!send_apdu (context, reader_name, send_buffer, 10, recv_buffer, &recv_length))
		return FALSE;

	return TRUE;
}

static char *
read_block (SCARDCONTEXT context, LPTSTR reader_name)
{
	DWORD recv_length, read_bytes = 0;
	gchar *ret = NULL;
	unsigned char block;
	unsigned char recv_buffer[32] = {0, };
	unsigned char read_apdu[5]  = {0xFF, 0xB0, 0x00, 0x00, 0x10};

	GString *new_contents = g_string_new (NULL);

	// Read 24byte from 28 to 30 block
	for (block = 0x1C; block < 0x1f; block++) {
		if (read_bytes == 24)
			break;

		read_apdu[3]= block; 
		recv_length = sizeof (recv_buffer);
		memset (recv_buffer, 0x00, sizeof (recv_buffer));

		if (!send_apdu (context, reader_name, read_apdu, 5, recv_buffer, &recv_length))
			break;

		if (recv_length == 0)
			break;

		DWORD i; 
		for (i = 0; i < recv_length - 2; i++) {
			gchar *c = g_strdup_printf ("%c", recv_buffer[i]);
			g_string_append_printf (new_contents, "%s", c);
			g_free (c);

			read_bytes++;

			if (24 == read_bytes)
				break;
		}
	}

	ret = g_strdup (new_contents->str);
	g_string_free (new_contents, TRUE);

	return ret;
}

static char *
read_uid (SCARDCONTEXT context, LPTSTR reader_name)
{
	DWORD recv_length;
	gchar *ret = NULL;
	unsigned char recv_buffer[32] = {0, };
	unsigned char send_buffer[32] = {0, };

	recv_length = sizeof (recv_buffer);

	memset (send_buffer, 0x00, sizeof (send_buffer));
	memset (recv_buffer, 0x00, sizeof (recv_buffer));
	memcpy (send_buffer, "\xFF\xCA\x00\x00\x00", 5);

	if (!send_apdu (context, reader_name, send_buffer, 5, recv_buffer, &recv_length))
		return NULL;

	if (recv_length == 0)
		return NULL;

	DWORD i;
	GString *new_contents = g_string_new (NULL);
	for (i = 0; i < recv_length-2; i++) {
		gchar *c = g_strdup_printf ("%02X", recv_buffer[i]);
		g_string_append_printf (new_contents, "%s", c);
		g_free (c);
	}

	ret = g_strdup (new_contents->str);
	g_string_free (new_contents, TRUE);

	return ret;
}

gboolean
nfc_data_get (pam_handle_t *pamh, char **data)
{
	int current_reader;
	LONG rv;
	SCARDCONTEXT hContext;
	SCARD_READERSTATE *rgReaderStates_t = NULL;
	SCARD_READERSTATE rgReaderStates[1];
	DWORD dwReaders = 0, dwReadersOld;
	DWORD timeout;
	LPSTR mszReaders = NULL;
	char *ptr, **readers = NULL;
	int nbReaders, i;
	int pnp = 1;
	gboolean ret = FALSE;

	rv = SCardEstablishContext (SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

	rgReaderStates[0].szReader = "\\\\?PnP?\\Notification";
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;

	rv = SCardGetStatusChange (hContext, 0, rgReaderStates, 1);
	if (rgReaderStates[0].dwEventState & SCARD_STATE_UNKNOWN) {
		timeout = 1000; /* 1 second timeout */
		pnp = 0;
	} else {
		timeout = TIMEOUT;
	}

	rv = SCardListReaders (hContext, NULL, NULL, &dwReaders);

	dwReadersOld = dwReaders;

	mszReaders = malloc (sizeof(char)*dwReaders);
	if (mszReaders == NULL) {
		pam_msg (pamh, _("Not enough memory"));
		goto out;
	}

	*mszReaders = '\0';
	rv = SCardListReaders (hContext, NULL, mszReaders, &dwReaders);

	/* Extract readers from the null separated string and get the total
	 * number of readers */
	nbReaders = 0;
	ptr = mszReaders;
	while (*ptr != '\0') {
		ptr += strlen(ptr)+1;
		nbReaders++;
	}

	if (SCARD_E_NO_READERS_AVAILABLE == rv || 0 == nbReaders) {
		pam_msg (pamh, _("Reader is not available."));
		goto out;
	}

	/* allocate the readers table */
	readers = calloc (nbReaders+1, sizeof(char *));
	if (NULL == readers) {
		pam_msg (pamh, _("Not enough memory"));
		goto out;
	}

	/* fill the readers table */
	nbReaders = 0;
	ptr = mszReaders;
	while (*ptr != '\0') {
		readers[nbReaders] = ptr;
		ptr += strlen(ptr)+1;
		nbReaders++;
	}

	/* allocate the ReaderStates table */
	rgReaderStates_t = calloc (nbReaders+1, sizeof(* rgReaderStates_t));
	if (NULL == rgReaderStates_t) {
		pam_msg (pamh, _("Not enough memory"));
		goto out;
	}
	/* Set the initial states to something we do not know
	 * The loop below will include this state to the dwCurrentState
	 */
	for (i=0; i<nbReaders; i++) {
		rgReaderStates_t[i].szReader = readers[i];
		rgReaderStates_t[i].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates_t[i].cbAtr = sizeof rgReaderStates_t[i].rgbAtr;
	}

	/* If Plug and Play is supported by the PC/SC layer */
	if (pnp) {
		rgReaderStates_t[nbReaders].szReader = "\\\\?PnP?\\Notification";
		rgReaderStates_t[nbReaders].dwCurrentState = SCARD_STATE_UNAWARE;
		nbReaders++;
	}

	/* Wait endlessly for all events in the list of readers
	 * We only stop in case of an error
	 */
	rv = SCardGetStatusChange (hContext, timeout, rgReaderStates_t, nbReaders);
	while ((rv == SCARD_S_SUCCESS)/* || (rv == SCARD_E_TIMEOUT)*/)
	{
		if (pnp) {
			if (rgReaderStates_t[nbReaders-1].dwEventState & SCARD_STATE_CHANGED) {
				pam_msg (pamh, _("Reader is not available."));
				goto out;
			}
		} else {
			/* A new reader appeared? */
			if ((SCardListReaders (hContext, NULL, NULL, &dwReaders) == SCARD_S_SUCCESS) && (dwReaders != dwReadersOld)) {
				goto out;
			}
		}
		/* Now we have an event, check all the readers in the list to see what
		 * happened */
		for (current_reader=0; current_reader < nbReaders; current_reader++) {
			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_CHANGED)
			{
				/* If something has changed the new state is now the current
				 * state */
				rgReaderStates_t[current_reader].dwCurrentState = rgReaderStates_t[current_reader].dwEventState;
			}
			else
				/* If nothing changed then skip to the next reader */
				continue;

			/* From here we know that the state for the current reader has
			 * changed because we did not pass through the continue statement
			 * above.
			 */

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_IGNORE) {
				pam_msg (pamh, _("Ignore this reader."));
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_UNKNOWN) {
				pam_msg (pamh, _("Unknown Reader."));
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_UNAVAILABLE) {
				pam_msg (pamh, _("Status unavailable."));
				goto out;
			}

			/* Card removed */
			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_EMPTY) {
				pam_msg (pamh, _("Tap your card."));
			}

			/* Card inserted */
			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_PRESENT) {
				char *uid = read_uid (hContext, mszReaders);
				if (authenticate (hContext, mszReaders)) {
					char *nfc_data = read_block (hContext, mszReaders);
					*data = g_strdup_printf ("%s%s", uid, nfc_data);
					g_free (nfc_data);
				}
				free (uid);

				ret = TRUE;
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_ATRMATCH) {
				pam_msg (pamh, _("ATR matches card."));
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_EXCLUSIVE) {
				pam_msg (pamh, _("Exclusive Mode."));
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_INUSE) {
				pam_msg (pamh, _("Shared Mode."));
				goto out;
			}

			if (rgReaderStates_t[current_reader].dwEventState & SCARD_STATE_MUTE) {
				pam_msg (pamh, _("Unresponsive card."));
				goto out;
			}
		} /* for */

		rv = SCardGetStatusChange(hContext, timeout, rgReaderStates_t, nbReaders);
	} /* while */

	if (rv == SCARD_E_TIMEOUT) {
		pam_msg (pamh, _("Input Timeout."));
	}

out:
	/* A reader disappeared */
	if (SCARD_E_UNKNOWN_READER == rv) {
		pam_msg (pamh, _("Reader is not available."));
	}

	/* We try to leave things as clean as possible */
	SCardReleaseContext(hContext);

	/* free memory possibly allocated */
	if (NULL != readers)
		free (readers);

	if (NULL != rgReaderStates_t)
		free (rgReaderStates_t);

	if (NULL != mszReaders)
		free (mszReaders);

	return ret;
}
