/*
 * Copyright (c) 2004, 2005 Darren Tucker.  All rights reserved.
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

#ifndef _SSH_AUDIT_H
# define _SSH_AUDIT_H

#include "loginrec.h"
#include "sshkey.h"

enum ssh_audit_event_type {
	SSH_LOGIN_EXCEED_MAXTRIES,
	SSH_LOGIN_ROOT_DENIED,
	SSH_AUTH_SUCCESS,
	SSH_AUTH_FAIL_NONE,
	SSH_AUTH_FAIL_PASSWD,
	SSH_AUTH_FAIL_KBDINT,	/* keyboard-interactive or challenge-response */
	SSH_AUTH_FAIL_PUBKEY,	/* ssh2 pubkey or ssh1 rsa */
	SSH_AUTH_FAIL_HOSTBASED,	/* ssh2 hostbased or ssh1 rhostsrsa */
	SSH_AUTH_FAIL_GSSAPI,
	SSH_INVALID_USER,
	SSH_NOLOGIN,		/* denied by /etc/nologin, not implemented */
	SSH_CONNECTION_CLOSE,	/* closed after attempting auth or session */
	SSH_CONNECTION_ABANDON,	/* closed without completing auth */
	SSH_AUDIT_UNKNOWN
};

enum ssh_audit_kex {
	SSH_AUDIT_UNSUPPORTED_CIPHER,
	SSH_AUDIT_UNSUPPORTED_MAC,
	SSH_AUDIT_UNSUPPORTED_COMPRESSION
};
typedef enum ssh_audit_event_type ssh_audit_event_t;

int	listening_for_clients(void);

void	audit_connection_from(const char *, int);
void	audit_event(ssh_audit_event_t);
void	audit_count_session_open(void);
void	audit_session_open(struct logininfo *);
void	audit_session_close(struct logininfo *);
int	audit_run_command(const char *);
void 	audit_end_command(int, const char *);
ssh_audit_event_t audit_classify_auth(const char *);
int	audit_keyusage(int, char *, int);
void	audit_key(int, int *, const struct sshkey *);
void	audit_unsupported(int);
void	audit_kex(int, char *, char *, char *, char *);
void	audit_unsupported_body(int);
void	audit_kex_body(int, char *, char *, char *, char *, pid_t, uid_t);
void	audit_session_key_free(int ctos);
void	audit_session_key_free_body(int ctos, pid_t, uid_t);
void	audit_destroy_sensitive_data(const char *, pid_t, uid_t);

#endif /* _SSH_AUDIT_H */
