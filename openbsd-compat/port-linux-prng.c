/*
 * Copyright (c) 2011 - 2020 Red Hat, Inc.
 *
 * Authors:
 *  Jan F. Chadima <jchadima@redhat.com>
 *  Jakub Jelen <jjelen@redhat.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Linux-specific portability code - prng support
 */

#include "includes.h"

#include <errno.h>
#include <string.h>
#include <openssl/rand.h>
#include <sys/random.h>

#include "log.h"

void
linux_seed(void)
{
	char *env = NULL;
	size_t randlen = 14, left;
	unsigned int flags = 0;
	unsigned char buf[256], *p;

	env = getenv("SSH_USE_STRONG_RNG");
	if (env && strcmp(env, "0") != 0) {
		size_t ienv = atoi(env);

		/* Max on buffer length */
		if (ienv > sizeof(buf))
			ienv = sizeof(buf);
		/* Minimum is always 14 B */
		if (ienv > randlen)
			randlen = ienv;
		flags = GRND_RANDOM;
	}

	errno = 0;
	left = randlen;
	p = buf;
	do {
		ssize_t len = getrandom(p, left, flags);
		if (len == -1) {
			if (errno != EINTR) {
				if (flags) {
					/* With the variable present, this is fatal error */
					fatal("Failed to seed from getrandom: %s", strerror(errno));
				} else {
					/* Otherwise we log the issue drop out from here */
					debug("Failed to seed from getrandom: %s", strerror(errno));
					return;
				}
			}
		} else if (len > 0) {
			left -= len;
			p += len;
		}
	} while (left > 0);

	RAND_seed(buf, randlen);
}
