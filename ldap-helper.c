/* $OpenBSD: ssh-pka-ldap.c,v 1.1 2009/12/03 03:34:42 jfch Exp $ */
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
#include "misc.h"
#include "xmalloc.h"
#include "ldapconf.h"
#include "ldapbody.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static int config_debug = 0;
int config_exclusive_config_file = 0;
static char *config_file_name = "/etc/ssh/ldap.conf";
static char *config_single_user = NULL;
static int config_verbose = SYSLOG_LEVEL_VERBOSE;
int config_warning_config_file = 0;
extern char *__progname;

static void
usage(void)
{
	fprintf(stderr, "usage: %s [options]\n",
	    __progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -d          Output the log messages to stderr.\n");
	fprintf(stderr, "  -e          Check the config file for unknown commands.\n");
	fprintf(stderr, "  -f file     Use alternate config file (default is /etc/ssh/ldap.conf).\n");
	fprintf(stderr, "  -s user     Do not demonize, send the user's key to stdout.\n");
	fprintf(stderr, "  -v          Increase verbosity of the debug output (implies -d).\n");
	fprintf(stderr, "  -w          Warn on unknown commands in the config file.\n");
	exit(1);
}

/*
 * Main program for the ssh pka ldap agent.
 */

int
main(int ac, char **av)
{
	int opt;
	FILE *outfile = NULL;

	__progname = ssh_get_progname(av[0]);

	log_init(__progname, SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 0);

	/*
	 * Initialize option structure to indicate that no values have been
	 * set.
	 */
	initialize_options();

	/* Parse command-line arguments. */
	while ((opt = getopt(ac, av, "def:s:vw")) != -1) {
		switch (opt) {
		case 'd':
			config_debug = 1;
			break;

		case 'e':
			config_exclusive_config_file = 1;
			config_warning_config_file = 1;
			break;

		case 'f':
			config_file_name = optarg;
			break;

		case 's':
			config_single_user = optarg;
			outfile = fdopen (dup (fileno (stdout)), "w");
			break;

		case 'v':
			config_debug = 1;
			if (config_verbose < SYSLOG_LEVEL_DEBUG3)
			    config_verbose++;
			break;

		case 'w':
			config_warning_config_file = 1;
			break;

		case '?':
		default:
			usage();
			break;
		}
	}

	/* Initialize loging */
	log_init(__progname, config_verbose, SYSLOG_FACILITY_AUTH, config_debug);

	if (ac != optind)
	    fatal ("illegal extra parameter %s", av[1]);

	/* Ensure that fds 0 and 2 are open or directed to /dev/null */
	if (config_debug == 0)
	    sanitise_stdfd();

	/* Read config file */
	read_config_file(config_file_name);
	fill_default_options();
	if (config_verbose == SYSLOG_LEVEL_DEBUG3) {
		debug3 ("=== Configuration ===");
		dump_config();
		debug3 ("=== *** ===");
	}

	ldap_checkconfig();
	ldap_do_connect();

	if (config_single_user) {
		process_user (config_single_user, outfile);
	} else {
		usage();
		fatal ("Not yet implemented");
/* TODO
 * open unix socket a run the loop on it
 */
	}

	ldap_do_close();
	return 0;
}
