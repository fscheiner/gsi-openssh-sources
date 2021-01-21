/* $OpenBSD: ldapbody.c,v 1.1 2009/12/03 03:34:42 jfch Exp $ */
/*
 * Copyright (c) 2009 Jan F. Chadima.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ldapincludes.h"
#include "log.h"
#include "xmalloc.h"
#include "ldapconf.h"
#include "ldapmisc.h"
#include "ldapbody.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "misc.h"

#define LDAPSEARCH_FORMAT "(&(objectclass=%c)(objectclass=ldapPublicKey)(uid=%u)%f)"
#define PUBKEYATTR "sshPublicKey"
#define LDAP_LOGFILE	"%s/ldap.%d"

static FILE *logfile = NULL;
static LDAP *ld;

static char *attrs[] = {
    PUBKEYATTR,
    NULL
};

void
ldap_checkconfig (void)
{
#ifdef HAVE_LDAP_INITIALIZE
		if (options.host == NULL && options.uri == NULL)
#else
		if (options.host == NULL)
#endif
		    fatal ("missing  \"host\" in config file");
}

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int
#if LDAP_API_VERSION > 3000
_rebind_proc (LDAP * ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *params)
#else
_rebind_proc (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid)
#endif
{
	struct timeval timeout;
	int rc;
#if defined(HAVE_LDAP_PARSE_RESULT) && defined(HAVE_LDAP_CONTROLS_FREE)
	LDAPMessage *result;
#endif /* HAVE_LDAP_PARSE_RESULT && HAVE_LDAP_CONTROLS_FREE */

	debug2 ("Doing LDAP rebind to %s", options.binddn);
	if (options.ssl == SSL_START_TLS) {
		if ((rc = ldap_start_tls_s (ld, NULL, NULL)) != LDAP_SUCCESS) {
			error ("ldap_starttls_s: %s", ldap_err2string (rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

#if !defined(HAVE_LDAP_PARSE_RESULT) || !defined(HAVE_LDAP_CONTROLS_FREE)
	return ldap_simple_bind_s (ld, options.binddn, options.bindpw);
#else
	if (ldap_simple_bind(ld, options.binddn, options.bindpw) < 0)
	    fatal ("ldap_simple_bind %s", ldap_err2string (ldap_get_lderrno (ld, 0, 0)));

	timeout.tv_sec = options.bind_timelimit;
	timeout.tv_usec = 0;
	result = NULL;
	if ((rc = ldap_result (ld, msgid, 0, &timeout, &result)) < 1) {
		error ("ldap_result %s", ldap_err2string (ldap_get_lderrno (ld, 0, 0)));
		ldap_msgfree (result);
		return LDAP_OPERATIONS_ERROR;
	}
	debug3 ("LDAP rebind to %s succesfull", options.binddn);
	return rc;
#endif
}
#else

static int
_rebind_proc (LDAP * ld, char **whop, char **credp, int *methodp, int freeit)
{
	if (freeit)
	    return LDAP_SUCCESS;

	*whop = strdup (options.binddn);
	*credp = strdup (options.bindpw);
	*methodp = LDAP_AUTH_SIMPLE;
	debug2 ("Doing LDAP rebind for %s", *whop);
	return LDAP_SUCCESS;
}
#endif

void
ldap_do_connect(void)
{
	int rc, msgid, ld_errno = 0;
	struct timeval timeout;
#if defined(HAVE_LDAP_PARSE_RESULT) && defined(HAVE_LDAP_CONTROLS_FREE)
	int parserc;
	LDAPMessage *result;
	LDAPControl **controls;
	int reconnect = 0;
#endif /* HAVE_LDAP_PARSE_RESULT && HAVE_LDAP_CONTROLS_FREE */

	debug ("LDAP do connect");

retry:
	if (reconnect) {
		debug3 ("Reconnecting with ld_errno %d", ld_errno);
		if (options.bind_policy == 0 ||
		    (ld_errno != LDAP_SERVER_DOWN && ld_errno != LDAP_TIMEOUT) ||
			reconnect > 5)
			    fatal ("Cannot connect to LDAP server");
	
		if (reconnect > 1)
			sleep (reconnect - 1);

		if (ld != NULL) {
			ldap_unbind (ld);
			ld = NULL;
		}
		logit("reconnecting to LDAP server...");
	}

	if (ld == NULL) {
		int rc;
		struct timeval tv;

#ifdef HAVE_LDAP_SET_OPTION
		if (options.debug > 0) {
#ifdef LBER_OPT_LOG_PRINT_FILE
			if (options.logdir) {
				char *logfilename;
				int logfilenamelen;

				logfilenamelen = strlen(LDAP_LOGFILE)
				    + strlen("000000") + strlen (options.logdir);
				logfilename = xmalloc (logfilenamelen);
				snprintf (logfilename, logfilenamelen, LDAP_LOGFILE, options.logdir, (int) getpid ());
				logfilename[logfilenamelen - 1] = 0;
				if ((logfile = fopen (logfilename, "a")) == NULL)
				    fatal ("cannot append to %s: %s", logfilename, strerror (errno));
				debug3 ("LDAP debug into %s", logfilename);
				free (logfilename);
				ber_set_option (NULL, LBER_OPT_LOG_PRINT_FILE, logfile);
			}
#endif
			if (options.debug) {
#ifdef LBER_OPT_DEBUG_LEVEL
				ber_set_option (NULL, LBER_OPT_DEBUG_LEVEL, &options.debug);
#endif /* LBER_OPT_DEBUG_LEVEL */
#ifdef LDAP_OPT_DEBUG_LEVEL
				(void) ldap_set_option (NULL, LDAP_OPT_DEBUG_LEVEL, &options.debug);
#endif /* LDAP_OPT_DEBUG_LEVEL */
				debug3 ("Set LDAP debug to %d", options.debug);
			}
		}
#endif /* HAVE_LDAP_SET_OPTION */

		ld = NULL;
#ifdef HAVE_LDAPSSL_INIT
		if (options.host != NULL) {
			if (options.ssl_on == SSL_LDAPS) {
				if ((rc = ldapssl_client_init (options.sslpath, NULL)) != LDAP_SUCCESS)
				    fatal ("ldapssl_client_init %s", ldap_err2string (rc));
				debug3 ("LDAPssl client init");
			}

			if (options.ssl_on != SSL_OFF) {
				if ((ld = ldapssl_init (options.host, options.port, 1)) == NULL)
				    fatal ("ldapssl_init failed");
				debug3 ("LDAPssl init");
			}
		}
#endif /* HAVE_LDAPSSL_INIT */

		/* continue with opening */
		if (ld == NULL) {
#if defined (HAVE_LDAP_START_TLS_S) || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))
			/* Some global TLS-specific options need to be set before we create our
			 * session context, so we set them here. */

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
			/* rand file */
			if (options.tls_randfile != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
				    options.tls_randfile)) != LDAP_SUCCESS)
					fatal ("ldap_set_option(LDAP_OPT_X_TLS_RANDOM_FILE): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS random file %s", options.tls_randfile);
			}
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

			/* ca cert file */
			if (options.tls_cacertfile != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE,
				    options.tls_cacertfile)) != LDAP_SUCCESS)
					error ("ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS CA cert file %s ", options.tls_cacertfile);
			}

			/* ca cert directory */
			if (options.tls_cacertdir != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTDIR,
				    options.tls_cacertdir)) != LDAP_SUCCESS)
					fatal ("ldap_set_option(LDAP_OPT_X_TLS_CACERTDIR): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS CA cert dir %s ", options.tls_cacertdir);
			}

			/* require cert? */
			if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
			    &options.tls_checkpeer)) != LDAP_SUCCESS)
				fatal ("ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT): %s",
				    ldap_err2string (rc));
			debug3 ("Set TLS check peer to %d ", options.tls_checkpeer);

			/* set cipher suite, certificate and private key: */
			if (options.tls_ciphers != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
				    options.tls_ciphers)) != LDAP_SUCCESS)
					fatal ("ldap_set_option(LDAP_OPT_X_TLS_CIPHER_SUITE): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS ciphers to %s ", options.tls_ciphers);
			}

			/* cert file */
			if (options.tls_cert != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_CERTFILE,
				    options.tls_cert)) != LDAP_SUCCESS)
					fatal ("ldap_set_option(LDAP_OPT_X_TLS_CERTFILE): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS cert file %s ", options.tls_cert);
			}

			/* key file */
			if (options.tls_key != NULL) {
				if ((rc = ldap_set_option (NULL, LDAP_OPT_X_TLS_KEYFILE,
				    options.tls_key)) != LDAP_SUCCESS)
					fatal ("ldap_set_option(LDAP_OPT_X_TLS_KEYFILE): %s",
					    ldap_err2string (rc));
				debug3 ("Set TLS key file %s ", options.tls_key);
			}
#endif
#ifdef HAVE_LDAP_INITIALIZE
			if (options.uri != NULL) {
				if ((rc = ldap_initialize (&ld, options.uri)) != LDAP_SUCCESS)
					fatal ("ldap_initialize %s", ldap_err2string (rc));
				debug3 ("LDAP initialize %s", options.uri);
			}
	}
#endif /* HAVE_LDAP_INTITIALIZE */

		/* continue with opening */
		if ((ld == NULL) && (options.host != NULL)) {
#ifdef HAVE_LDAP_INIT
			if ((ld = ldap_init (options.host, options.port)) == NULL)
			    fatal ("ldap_init failed");
			debug3 ("LDAP init %s:%d", options.host, options.port);
#else
			if ((ld = ldap_open (options.host, options.port)) == NULL)
			    fatal ("ldap_open failed");
			debug3 ("LDAP open %s:%d", options.host, options.port);
#endif /* HAVE_LDAP_INIT */
		}

		if (ld == NULL)
			fatal ("no way to open ldap");

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
		if (options.ssl == SSL_LDAPS) {
			if ((rc = ldap_set_option (ld, LDAP_OPT_X_TLS, &options.tls_checkpeer)) != LDAP_SUCCESS)
				fatal ("ldap_set_option(LDAP_OPT_X_TLS) %s", ldap_err2string (rc));
			debug3 ("LDAP set LDAP_OPT_X_TLS_%d", options.tls_checkpeer);
		}
#endif /* LDAP_OPT_X_TLS */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
		(void) ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION,
		    &options.ldap_version);
#else
		ld->ld_version = options.ldap_version;
#endif
		debug3 ("LDAP set version to %d", options.ldap_version);

#if LDAP_SET_REBIND_PROC_ARGS == 3
		ldap_set_rebind_proc (ld, _rebind_proc, NULL);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
		ldap_set_rebind_proc (ld, _rebind_proc);
#else
#warning unknown LDAP_SET_REBIND_PROC_ARGS
#endif
		debug3 ("LDAP set rebind proc");

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DEREF)
		(void) ldap_set_option (ld, LDAP_OPT_DEREF, &options.deref);
#else
		ld->ld_deref = options.deref;
#endif
		debug3 ("LDAP set deref to %d", options.deref);

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMELIMIT)
		(void) ldap_set_option (ld, LDAP_OPT_TIMELIMIT,
		    &options.timelimit);
#else
		ld->ld_timelimit = options.timelimit;
#endif
		debug3 ("LDAP set timelimit to %d", options.timelimit);

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_X_OPT_CONNECT_TIMEOUT)
		/*
		 * This is a new option in the Netscape SDK which sets 
		 * the TCP connect timeout. For want of a better value,
		 * we use the bind_timelimit to control this.
		 */
		timeout = options.bind_timelimit * 1000;
		(void) ldap_set_option (ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
		debug3 ("LDAP set opt connect timeout to %d", timeout);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
		tv.tv_sec = options.bind_timelimit;
		tv.tv_usec = 0;
		(void) ldap_set_option (ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
		debug3 ("LDAP set opt network timeout to %ld.0", tv.tv_sec);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_REFERRALS)
		(void) ldap_set_option (ld, LDAP_OPT_REFERRALS,
		    options.referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
		debug3 ("LDAP set referrals to %d", options.referrals);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_RESTART)
		(void) ldap_set_option (ld, LDAP_OPT_RESTART,
		    options.restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
		debug3 ("LDAP set restart to %d", options.restart);
#endif

#ifdef HAVE_LDAP_START_TLS_S
		if (options.ssl == SSL_START_TLS) {
			int version;

			if (ldap_get_option (ld, LDAP_OPT_PROTOCOL_VERSION, &version)
			    == LDAP_SUCCESS) {
				if (version < LDAP_VERSION3) {
					version = LDAP_VERSION3;
					(void) ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION,
					    &version);
					debug3 ("LDAP set version to %d", version);
				}
			}

			if ((rc = ldap_start_tls_s (ld, NULL, NULL)) != LDAP_SUCCESS)
			    fatal ("ldap_starttls_s: %s", ldap_err2string (rc));
			debug3 ("LDAP start TLS");
		}
#endif /* HAVE_LDAP_START_TLS_S */
	}

	if ((msgid = ldap_simple_bind (ld, options.binddn,
	    options.bindpw)) == -1) {
		ld_errno = ldap_get_lderrno (ld, 0, 0);

		error ("ldap_simple_bind %s", ldap_err2string (ld_errno));
		reconnect++;
		goto retry;
	}
	debug3 ("LDAP simple bind (%s)", options.binddn);

	timeout.tv_sec = options.bind_timelimit;
	timeout.tv_usec = 0;
	if ((rc = ldap_result (ld, msgid, 0, &timeout, &result)) < 1) {
		ld_errno = ldap_get_lderrno (ld, 0, 0);

		error ("ldap_result %s", ldap_err2string (ld_errno));
		reconnect++;
		goto retry;
	}
	debug3 ("LDAP result in time");

#if defined(HAVE_LDAP_PARSE_RESULT) && defined(HAVE_LDAP_CONTROLS_FREE)
	controls = NULL;
	if ((parserc = ldap_parse_result (ld, result, &rc, 0, 0, 0, &controls, 1)) != LDAP_SUCCESS)
	    fatal ("ldap_parse_result %s", ldap_err2string (parserc));
	debug3 ("LDAP parse result OK");

	if (controls != NULL) {
		ldap_controls_free (controls);
	}
#else
	rc = ldap_result2error (session->ld, result, 1);
#endif
	if (rc != LDAP_SUCCESS)
	    fatal ("error trying to bind as user \"%s\" (%s)",
		options.binddn, ldap_err2string (rc));

	debug2 ("LDAP do connect OK");
}

void
process_user (const char *user, FILE *output)
{
	LDAPMessage *res, *e;
	char *buffer, *format;
	int rc, i;
	struct timeval timeout;

	debug ("LDAP process user");

	/* quick check for attempts to be evil */
	if ((strchr(user, '(') != NULL) || (strchr(user, ')') != NULL) ||
	    (strchr(user, '*') != NULL) || (strchr(user, '\\') != NULL)) {
		logit ("illegal user name %s not processed", user);
		return;
	}

	/* build  filter for LDAP request */
	format = LDAPSEARCH_FORMAT;
	if (options.search_format != NULL)
		format = options.search_format;
	buffer = percent_expand(format, "c", options.account_class, "u", user, "f", options.ssh_filter, (char *)NULL);

	debug3 ("LDAP search scope = %d %s", options.scope, buffer);

	timeout.tv_sec = options.timelimit;
	timeout.tv_usec = 0;
	if ((rc = ldap_search_st(ld, options.base, options.scope, buffer, attrs, 0, &timeout, &res)) != LDAP_SUCCESS) {
		error ("ldap_search_st(): %s", ldap_err2string (rc));
		free (buffer);
		return;
	}

	/* free */
	free (buffer);

	for (e = ldap_first_entry(ld, res); e != NULL; e = ldap_next_entry(ld, e)) {
		int num;
		struct berval **keys;

		keys = ldap_get_values_len(ld, e, PUBKEYATTR);
		num = ldap_count_values_len(keys);
		for (i = 0 ; i < num ; i++) {
			char *cp; //, *options = NULL;

			for (cp = keys[i]->bv_val; *cp == ' ' || *cp == '\t'; cp++);
			if (!*cp || *cp == '\n' || *cp == '#')
			    continue;

			/* We have found the desired key. */
			fprintf (output, "%s\n", keys[i]->bv_val);
		}

		ldap_value_free_len(keys);
	}

	ldap_msgfree(res);
	debug2 ("LDAP process user finished");
}

void
ldap_do_close(void)
{
	int rc;

	debug ("LDAP do close");
	if ((rc = ldap_unbind_ext(ld, NULL, NULL)) != LDAP_SUCCESS)
	    fatal ("ldap_unbind_ext: %s",
                                    ldap_err2string (rc));

	ld = NULL;
	debug2 ("LDAP do close OK");
	return;
}

