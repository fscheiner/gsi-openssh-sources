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

#include "ldapincludes.h"
#include "ldap-helper.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "ldapconf.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/* Keyword tokens. */

typedef enum {
	lBadOption,
	lHost, lURI, lBase, lBindDN, lBindPW, lRootBindDN,
	lScope, lDeref, lPort, lTimeLimit, lBind_TimeLimit,
	lLdap_Version, lBind_Policy, lSSLPath, lSSL, lReferrals,
	lRestart, lTLS_CheckPeer, lTLS_CaCertFile,
	lTLS_CaCertDir, lTLS_Ciphers, lTLS_Cert, lTLS_Key,
	lTLS_RandFile, lLogDir, lDebug, lSSH_Filter, lSearch_Format,
	lAccountClass, lDeprecated, lUnsupported
} OpCodes;

/* Textual representations of the tokens. */

static struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "URI", lURI },
	{ "Base", lBase },
	{ "BindDN", lBindDN },
	{ "BindPW", lBindPW },
	{ "RootBindDN", lRootBindDN },
	{ "Host", lHost },
	{ "Port", lPort },
	{ "Scope", lScope },
	{ "Deref", lDeref },
	{ "TimeLimit", lTimeLimit },
	{ "TimeOut", lTimeLimit },
	{ "Bind_Timelimit", lBind_TimeLimit },
	{ "Network_TimeOut", lBind_TimeLimit },
/*
 * Todo
 * SIZELIMIT
 */
	{ "Ldap_Version", lLdap_Version },
	{ "Version", lLdap_Version },
	{ "Bind_Policy", lBind_Policy },
	{ "SSLPath", lSSLPath },
	{ "SSL", lSSL },
	{ "Referrals", lReferrals },
	{ "Restart", lRestart },
	{ "TLS_CheckPeer", lTLS_CheckPeer },
	{ "TLS_ReqCert", lTLS_CheckPeer },
	{ "TLS_CaCertFile", lTLS_CaCertFile },
	{ "TLS_CaCert", lTLS_CaCertFile },
	{ "TLS_CaCertDir", lTLS_CaCertDir },
	{ "TLS_Ciphers", lTLS_Ciphers },
	{ "TLS_Cipher_Suite", lTLS_Ciphers },
	{ "TLS_Cert", lTLS_Cert },
	{ "TLS_Certificate", lTLS_Cert },
	{ "TLS_Key", lTLS_Key },
	{ "TLS_RandFile", lTLS_RandFile },
/*
 * Todo
 * TLS_CRLCHECK
 * TLS_CRLFILE
 */
	{ "LogDir", lLogDir },
	{ "Debug", lDebug },
	{ "SSH_Filter", lSSH_Filter },
	{ "search_format", lSearch_Format },
	{ "AccountClass", lAccountClass },
	{ NULL, lBadOption }
};

/* Configuration ptions. */

Options options;

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */

static OpCodes
parse_token(const char *cp, const char *filename, int linenum)
{
	u_int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	if (config_warning_config_file) 
	    logit("%s: line %d: Bad configuration option: %s",
		filename, linenum, cp);
	return lBadOption;
}

/* Characters considered whitespace in strsep calls. */
#define WHITESPACE " \t\r\n"

/* return next token in configuration line */
static char *
ldap_strdelim(char **s)
{
      char *old;
      int wspace = 0;

      if (*s == NULL)
              return NULL;

      old = *s;

      *s = strpbrk(*s, WHITESPACE);
      if (*s == NULL)
              return (old);

      *s[0] = '\0';

      /* Skip any extra whitespace after first token */
      *s += strspn(*s + 1, WHITESPACE) + 1;
      if (*s[0] == '=' && !wspace)
              *s += strspn(*s + 1, WHITESPACE) + 1;

      return (old);
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
#define WHITESPACE " \t\r\n"

static int
process_config_line(char *line, const char *filename, int linenum)
{
	char *s, **charptr, **xstringptr, *endofnumber, *keyword, *arg;
	char *rootbinddn = NULL;
	int opcode, *intptr, value;
	size_t len;

	/* Strip trailing whitespace */
	for (len = strlen(line) - 1; len > 0; len--) {
		if (strchr(WHITESPACE, line[len]) == NULL)
			break;
		line[len] = '\0';
	}

	s = line;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	if ((keyword = ldap_strdelim(&s)) == NULL)
		return 0;
	/* Ignore leading whitespace. */
	if (*keyword == '\0')
		keyword = ldap_strdelim(&s);
	if (keyword == NULL || !*keyword || *keyword == '\n' || *keyword == '#')
		return 0;

	opcode = parse_token(keyword, filename, linenum);

	switch (opcode) {
	case lBadOption:
		/* don't panic, but count bad options */
		return -1;
		/* NOTREACHED */

	case lHost:
		xstringptr = &options.host;
parse_xstring:
		if (!s || *s == '\0')
		    fatal("%s line %d: missing dn",filename,linenum);
		if (*xstringptr == NULL)
		    *xstringptr = xstrdup(s);
		return 0;

	case lURI:
		xstringptr = &options.uri;
		goto parse_xstring;

	case lBase:
		xstringptr = &options.base;
		goto parse_xstring;

	case lBindDN:
		xstringptr = &options.binddn;
		goto parse_xstring;

	case lBindPW:
		charptr = &options.bindpw;
parse_string:
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (*charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case lRootBindDN:
		xstringptr = &rootbinddn;
		goto parse_xstring;

	case lScope:
		intptr = &options.scope;
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing sub/one/base argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (strcasecmp (arg, "sub") == 0 || strcasecmp (arg, "subtree") == 0)
			value = LDAP_SCOPE_SUBTREE;
		else if (strcasecmp (arg, "one") == 0)
			value = LDAP_SCOPE_ONELEVEL;
		else if (strcasecmp (arg, "base") == 0)
			value = LDAP_SCOPE_BASE;
		else
			fatal("%.200s line %d: Bad sub/one/base argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lDeref:
		intptr = &options.scope;
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing never/searching/finding/always argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (!strcasecmp (arg, "never"))
			value = LDAP_DEREF_NEVER;
		else if (!strcasecmp (arg, "searching"))
			value = LDAP_DEREF_SEARCHING;
		else if (!strcasecmp (arg, "finding"))
			value = LDAP_DEREF_FINDING;
		else if (!strcasecmp (arg, "always"))
			value = LDAP_DEREF_ALWAYS;
		else
			fatal("%.200s line %d: Bad never/searching/finding/always argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lPort:
		intptr = &options.port;
parse_int:
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (arg[0] < '0' || arg[0] > '9')
			fatal("%.200s line %d: Bad number.", filename, linenum);

		/* Octal, decimal, or hex format? */
		value = strtol(arg, &endofnumber, 0);
		if (arg == endofnumber)
			fatal("%.200s line %d: Bad number.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lTimeLimit:
		intptr = &options.timelimit;
parse_time:
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		if ((value = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lBind_TimeLimit:
		intptr = &options.bind_timelimit;
		goto parse_time;

	case lLdap_Version:
		intptr = &options.ldap_version;
		goto parse_int;

	case lBind_Policy:
		intptr = &options.bind_policy;
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing soft/hard argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (strcasecmp(arg, "hard") == 0 || strcasecmp(arg, "hard_open") == 0 || strcasecmp(arg, "hard_init") == 0)
			value = 1;
		else if (strcasecmp(arg, "soft") == 0)
			value = 0;
		else
			fatal("%.200s line %d: Bad soft/hard argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lSSLPath:
		charptr = &options.sslpath;
		goto parse_string;

	case lSSL:
		intptr = &options.ssl;
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing yes/no/start_tls argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (strcasecmp(arg, "yes") == 0 || strcasecmp(arg, "true") == 0 || strcasecmp(arg, "on") == 0)
			value = SSL_LDAPS;
		else if (strcasecmp(arg, "no") == 0 || strcasecmp(arg, "false") == 0 || strcasecmp(arg, "off") == 0)
			value = SSL_OFF;
		else if (!strcasecmp (arg, "start_tls"))
			value = SSL_START_TLS;
		else
			fatal("%.200s line %d: Bad yes/no/start_tls argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lReferrals:
		intptr = &options.referrals;
parse_flag:
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing yes/no argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (strcasecmp(arg, "yes") == 0 || strcasecmp(arg, "true") == 0 || strcasecmp(arg, "on") == 0)
			value = 1;
		else if (strcasecmp(arg, "no") == 0 || strcasecmp(arg, "false") == 0 || strcasecmp(arg, "off") == 0)
			value = 0;
		else
			fatal("%.200s line %d: Bad yes/no argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lRestart:
		intptr = &options.restart;
		goto parse_flag;

	case lTLS_CheckPeer:
		intptr = &options.tls_checkpeer;
		arg = ldap_strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing never/hard/demand/alow/try argument.", filename, linenum);
		value = 0;	/* To avoid compiler warning... */
		if (strcasecmp(arg, "never") == 0 || strcasecmp(arg, "no") == 0 || strcasecmp(arg, "false") == 0 || strcasecmp(arg, "off") == 0)
			value = LDAP_OPT_X_TLS_NEVER;
		else if (strcasecmp(arg, "hard") == 0 || strcasecmp(arg, "yes") == 0 || strcasecmp(arg, "true") == 0 || strcasecmp(arg, "on") == 0)
			value = LDAP_OPT_X_TLS_HARD;
		else if (strcasecmp(arg, "demand") == 0)
			value = LDAP_OPT_X_TLS_DEMAND;
		else if (strcasecmp(arg, "allow") == 0)
			value = LDAP_OPT_X_TLS_ALLOW;
		else if (strcasecmp(arg, "try") == 0)
			value = LDAP_OPT_X_TLS_TRY;
		else
			fatal("%.200s line %d: Bad never/hard/demand/alow/try argument.", filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case lTLS_CaCertFile:
		charptr = &options.tls_cacertfile;
		goto parse_string;

	case lTLS_CaCertDir:
		charptr = &options.tls_cacertdir;
		goto parse_string;

	case lTLS_Ciphers:
		xstringptr = &options.tls_ciphers;
		goto parse_xstring;

	case lTLS_Cert:
		charptr = &options.tls_cert;
		goto parse_string;

	case lTLS_Key:
		charptr = &options.tls_key;
		goto parse_string;

	case lTLS_RandFile:
		charptr = &options.tls_randfile;
		goto parse_string;

	case lLogDir:
		charptr = &options.logdir;
		goto parse_string;

	case lDebug:
		intptr = &options.debug;
		goto parse_int;

	case lSSH_Filter:
		xstringptr = &options.ssh_filter;
		goto parse_xstring;

	case lSearch_Format:
		charptr = &options.search_format;
		goto parse_string;

	case lAccountClass:
		charptr = &options.account_class;
		goto parse_string;

	case lDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		return 0;

	case lUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		return 0;

	default:
		fatal("process_config_line: Unimplemented opcode %d", opcode);
	}

	/* Check that there is no garbage at end of line. */
	if ((arg = ldap_strdelim(&s)) != NULL && *arg != '\0') {
		fatal("%.200s line %d: garbage at end of line; \"%.200s\".",
		    filename, linenum, arg);
	}
	return 0;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */

void
read_config_file(const char *filename)
{
	FILE *f;
	char line[1024];
	int linenum;
	int bad_options = 0;
	struct stat sb;

	if ((f = fopen(filename, "r")) == NULL)
		fatal("fopen %s: %s", filename, strerror(errno));

	if (fstat(fileno(f), &sb) == -1)
		fatal("fstat %s: %s", filename, strerror(errno));
	if (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
	    (sb.st_mode & 022) != 0))
		fatal("Bad owner or permissions on %s", filename);

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	while (fgets(line, sizeof(line), f)) {
		/* Update line number counter. */
		linenum++;
		if (process_config_line(line, filename, linenum) != 0)
			bad_options++;
	}
	fclose(f);
	if ((bad_options > 0) && config_exclusive_config_file) 
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

void
initialize_options(void)
{
	memset(&options, 'X', sizeof(options));
	options.host = NULL;
	options.uri = NULL;
	options.base = NULL;
	options.binddn = NULL;
	options.bindpw = NULL;
	options.scope = -1;
	options.deref = -1;
	options.port = -1;
	options.timelimit = -1;
	options.bind_timelimit = -1;
	options.ldap_version = -1;
	options.bind_policy = -1;
	options.sslpath = NULL;
	options.ssl = -1;
	options.referrals = -1;
	options.restart = -1;
	options.tls_checkpeer = -1;
	options.tls_cacertfile = NULL;
	options.tls_cacertdir = NULL;
	options.tls_ciphers = NULL;
	options.tls_cert = NULL;
	options.tls_key = NULL;
	options.tls_randfile = NULL;
	options.logdir = NULL;
	options.debug = -1;
	options.ssh_filter = NULL;
	options.search_format = NULL;
	options.account_class = NULL;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */

void
fill_default_options(void)
{
	if (options.uri != NULL) {
		LDAPURLDesc *ludp;

		if (ldap_url_parse(options.uri, &ludp) == LDAP_SUCCESS) {
			if (options.ssl == -1) {
				if (strcmp (ludp->lud_scheme, "ldap") == 0)
				    options.ssl = 2;
				if (strcmp (ludp->lud_scheme, "ldapi") == 0)
				    options.ssl = 0;
				else if (strcmp (ludp->lud_scheme, "ldaps") == 0)
				    options.ssl = 1;
			}
			if (options.host == NULL)
			    options.host = xstrdup (ludp->lud_host);
			if (options.port == -1)
			    options.port = ludp->lud_port;

			ldap_free_urldesc (ludp);
		}
	} 
	if (options.ssl == -1)
	    options.ssl = SSL_START_TLS;
	if (options.port == -1)
	    options.port = (options.ssl == 0) ? 389 : 636;
	if (options.uri == NULL) {
		int len;
#define MAXURILEN 4096

		options.uri = xmalloc (MAXURILEN);
		len = snprintf (options.uri, MAXURILEN, "ldap%s://%s:%d",
		    (options.ssl == 0) ? "" : "s", options.host, options.port);
		options.uri[MAXURILEN - 1] = 0;
		options.uri = xreallocarray(options.uri, len + 1, 1);
	}
	if (options.binddn == NULL)
	    options.binddn = "";
	if (options.bindpw == NULL)
	    options.bindpw = "";
	if (options.scope == -1)
	    options.scope = LDAP_SCOPE_SUBTREE;
	if (options.deref == -1)
	    options.deref = LDAP_DEREF_NEVER;
	if (options.timelimit == -1)
	    options.timelimit = 10;
	if (options.bind_timelimit == -1)
	    options.bind_timelimit = 10;
	if (options.ldap_version == -1)
	    options.ldap_version = 3;
	if (options.bind_policy == -1)
	    options.bind_policy = 1;
	if (options.referrals == -1)
	    options.referrals = 1;
	if (options.restart == -1)
	    options.restart = 1;
	if (options.tls_checkpeer == -1)
	    options.tls_checkpeer = LDAP_OPT_X_TLS_HARD;
	if (options.debug == -1)
	    options.debug = 0;
	if (options.ssh_filter == NULL)
	    options.ssh_filter = "";
	if (options.account_class == NULL)
	    options.account_class = "posixAccount";
}

static const char *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	for (i = 0; keywords[i].name != NULL; i++)
	    if (keywords[i].opcode == code)
		return(keywords[i].name);
	return "UNKNOWN";
}

static void
dump_cfg_string(OpCodes code, const char *val)
{
	if (val == NULL)
	    debug3("%s <UNDEFINED>", lookup_opcode_name(code));
	else
	    debug3("%s %s", lookup_opcode_name(code), val);
}

static void
dump_cfg_int(OpCodes code, int val)
{
	if (val == -1)
	    debug3("%s <UNDEFINED>", lookup_opcode_name(code));
	else
	    debug3("%s %d", lookup_opcode_name(code), val);
}

struct names {
	int value;
	char *name;
};

static void
dump_cfg_namedint(OpCodes code, int val, struct names *names)
{
	u_int i;

	if (val == -1)
	    debug3("%s <UNDEFINED>", lookup_opcode_name(code));
	else {
		for (i = 0; names[i].value != -1; i++)
	 	    if (names[i].value == val) {
	    		debug3("%s %s", lookup_opcode_name(code), names[i].name);
			    return;
		}
		debug3("%s unknown: %d", lookup_opcode_name(code), val);
	}
}

static struct names _yesnotls[] = {
	{ 0, "No" },
	{ 1, "Yes" },
	{ 2, "Start_TLS" },
	{ -1, NULL }};

static struct names _scope[] = {
	{ LDAP_SCOPE_BASE, "Base" },
	{ LDAP_SCOPE_ONELEVEL, "One" },
	{ LDAP_SCOPE_SUBTREE, "Sub"},
	{ -1, NULL }};

static struct names _deref[] = {
	{ LDAP_DEREF_NEVER, "Never" },
	{ LDAP_DEREF_SEARCHING, "Searching" },
	{ LDAP_DEREF_FINDING, "Finding" },
	{ LDAP_DEREF_ALWAYS, "Always" },
	{ -1, NULL }};

static struct names _yesno[] = {
	{ 0, "No" },
	{ 1, "Yes" },
	{ -1, NULL }};

static struct names _bindpolicy[] = {
	{ 0, "Soft" },
	{ 1, "Hard" },
	{ -1, NULL }};

static struct names _checkpeer[] = {
	{ LDAP_OPT_X_TLS_NEVER, "Never" },
	{ LDAP_OPT_X_TLS_HARD, "Hard" },
	{ LDAP_OPT_X_TLS_DEMAND, "Demand" },
	{ LDAP_OPT_X_TLS_ALLOW, "Allow" },
	{ LDAP_OPT_X_TLS_TRY, "TRY" },
	{ -1, NULL }};

void
dump_config(void)
{
	dump_cfg_string(lURI, options.uri);
	dump_cfg_string(lHost, options.host);
	dump_cfg_int(lPort, options.port);
	dump_cfg_namedint(lSSL, options.ssl, _yesnotls);
	dump_cfg_int(lLdap_Version, options.ldap_version);
	dump_cfg_int(lTimeLimit, options.timelimit);
	dump_cfg_int(lBind_TimeLimit, options.bind_timelimit);
	dump_cfg_string(lBase, options.base);
	dump_cfg_string(lBindDN, options.binddn);
	dump_cfg_string(lBindPW, options.bindpw);
	dump_cfg_namedint(lScope, options.scope, _scope);
	dump_cfg_namedint(lDeref, options.deref, _deref);
	dump_cfg_namedint(lReferrals, options.referrals, _yesno);
	dump_cfg_namedint(lRestart, options.restart, _yesno);
	dump_cfg_namedint(lBind_Policy, options.bind_policy, _bindpolicy);
	dump_cfg_string(lSSLPath, options.sslpath);
	dump_cfg_namedint(lTLS_CheckPeer, options.tls_checkpeer, _checkpeer);
	dump_cfg_string(lTLS_CaCertFile, options.tls_cacertfile);
	dump_cfg_string(lTLS_CaCertDir, options.tls_cacertdir);
	dump_cfg_string(lTLS_Ciphers, options.tls_ciphers);
	dump_cfg_string(lTLS_Cert, options.tls_cert);
	dump_cfg_string(lTLS_Key, options.tls_key);
	dump_cfg_string(lTLS_RandFile, options.tls_randfile);
	dump_cfg_string(lLogDir, options.logdir);
	dump_cfg_int(lDebug, options.debug);
	dump_cfg_string(lSSH_Filter, options.ssh_filter);
	dump_cfg_string(lSearch_Format, options.search_format);
	dump_cfg_string(lAccountClass, options.account_class);
}

