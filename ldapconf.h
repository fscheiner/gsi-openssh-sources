/* $OpenBSD: ldapconf.c,v 1.1 2009/12/03 03:34:42 jfch Exp $ */
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

#ifndef LDAPCONF_H
#define LDAPCONF_H

#define SSL_OFF          0
#define SSL_LDAPS        1
#define SSL_START_TLS    2

/* Data structure for representing option data. */

typedef struct {
	char *host;
	char *uri;
	char *base;
	char *binddn;
	char *bindpw;
	int scope;
	int deref;
	int port;
	int timelimit;
	int bind_timelimit;
	int ldap_version;
	int bind_policy;
	char *sslpath;
	int ssl;
	int referrals;
	int restart;
	int tls_checkpeer;
	char *tls_cacertfile;
	char *tls_cacertdir;
	char *tls_ciphers;
	char *tls_cert;
	char *tls_key;
	char *tls_randfile;
	char *logdir;
	int debug;
	char *ssh_filter;
	char *search_format;
	char *account_class;
}       Options;

extern Options options;

void read_config_file(const char *);
void initialize_options(void);
void fill_default_options(void);
void dump_config(void);

#endif /* LDAPCONF_H */
