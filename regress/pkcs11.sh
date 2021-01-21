#
#  Copyright (c) 2017 Red Hat
#
#  Authors: Jakub Jelen <jjelen@redhat.com>
#
#  Permission to use, copy, modify, and distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

tid="pkcs11 tests with soft token"

TEST_SSH_PIN=""
TEST_SSH_PKCS11=$OBJ/soft-pkcs11.so

test -f "$TEST_SSH_PKCS11" || fatal "$TEST_SSH_PKCS11 does not exist"

# requires ssh-agent built with correct path to ssh-pkcs11-helper
# otherwise it fails to start the helper
strings ${TEST_SSH_SSHAGENT} | grep "$TEST_SSH_SSHPKCS11HELPER"
if [ $? -ne 0 ]; then
	fatal "Needs to reconfigure with --libexecdir=\`pwd\` or so"
fi

# setup environment for soft-pkcs11 token
SOFTPKCS11RC=$OBJ/pkcs11.info
rm -f $SOFTPKCS11RC
export SOFTPKCS11RC
# prevent ssh-agent from calling ssh-askpass
SSH_ASKPASS=/usr/bin/true
export SSH_ASKPASS
unset DISPLAY

# start command w/o tty, so ssh accepts pin from stdin (from agent-pkcs11.sh)
notty() {
	perl -e 'use POSIX; POSIX::setsid();
	    if (fork) { wait; exit($? >> 8); } else { exec(@ARGV) }' "$@"
}

create_key() {
	ID=$1
	LABEL=$2
	rm -f $OBJ/pkcs11-${ID}.key $OBJ/pkcs11-${ID}.crt
	openssl genrsa -out $OBJ/pkcs11-${ID}.key 2048 > /dev/null 2>&1
	chmod 600 $OBJ/pkcs11-${ID}.key
	openssl req -key $OBJ/pkcs11-${ID}.key -new -x509 \
	    -out $OBJ/pkcs11-${ID}.crt -text -subj '/CN=pkcs11 test' >/dev/null
	printf "${ID}\t${LABEL}\t$OBJ/pkcs11-${ID}.crt\t$OBJ/pkcs11-${ID}.key\n" \
	    >> $SOFTPKCS11RC
}

trace "Create a key pairs on soft token"
ID1="02"
ID2="04"
create_key "$ID1" "SSH RSA Key"
create_key "$ID2" "SSH RSA Key 2"

trace "List the keys in the ssh-keygen with PKCS#11 URIs"
${SSHKEYGEN} -D ${TEST_SSH_PKCS11} > $OBJ/token_keys
if [ $? -ne 0 ]; then
	fail "keygen fails to enumerate keys on PKCS#11 token"
fi
grep "pkcs11:" $OBJ/token_keys > /dev/null
if [ $? -ne 0 ]; then
	fail "The keys from ssh-keygen do not contain PKCS#11 URI as a comment"
fi
tail -n 1 $OBJ/token_keys > $OBJ/authorized_keys_$USER


trace "Simple connect with ssh (without PKCS#11 URI)"
echo ${TEST_SSH_PIN} | notty ${SSH} -I ${TEST_SSH_PKCS11} \
    -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with pkcs11 failed (exit code $r)"
fi


trace "Connect with PKCS#11 URI"
trace "  (second key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=${ID2}?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (first key should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:id=${ID1}?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "ssh connect with PKCS#11 URI succeeded (should fail)"
fi

trace "Connect with various filtering options in PKCS#11 URI"
trace "  (by object label, second key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:object=SSH%20RSA%20Key%202?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (by object label, first key should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:object=SSH%20RSA%20Key?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "ssh connect with PKCS#11 URI succeeded (should fail)"
fi

trace "  (by token label, second key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=${ID2};token=SoftToken%20(token)?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI failed (exit code $r)"
fi

trace "  (by wrong token label, should fail)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
     -i "pkcs11:token=SoftToken?module-path=${TEST_SSH_PKCS11}" somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "ssh connect with PKCS#11 URI succeeded (should fail)"
fi




trace "Test PKCS#11 URI specification in configuration files"
echo "IdentityFile \"pkcs11:id=${ID2}?module-path=${TEST_SSH_PKCS11}\"" \
    >> $OBJ/ssh_proxy
trace "  (second key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI in config failed (exit code $r)"
fi

trace "  (first key should fail)"
head -n 1 $OBJ/token_keys > $OBJ/authorized_keys_$USER
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -eq 5 ]; then
	fail "ssh connect with PKCS#11 URI in config succeeded (should fail)"
fi
sed -i -e "/IdentityFile/d" $OBJ/ssh_proxy

trace "Test PKCS#11 URI specification in configuration files with bogus spaces"
echo "IdentityFile \"    pkcs11:id=${ID1}?module-path=${TEST_SSH_PKCS11}    \"" \
    >> $OBJ/ssh_proxy
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI with bogus spaces in config failed" \
	    "(exit code $r)"
fi
sed -i -e "/IdentityFile/d" $OBJ/ssh_proxy


trace "Combination of PKCS11Provider and PKCS11URI on commandline"
trace "  (first key should succeed)"
echo ${TEST_SSH_PIN} | notty ${SSH} -F $OBJ/ssh_proxy \
    -i "pkcs11:id=${ID1}" -I ${TEST_SSH_PKCS11} somehost exit 5
r=$?
if [ $r -ne 5 ]; then
	fail "ssh connect with PKCS#11 URI and provider combination" \
	    "failed (exit code $r)"
fi

trace "Regress: Missing provider in PKCS11URI option"
${SSH} -F $OBJ/ssh_proxy \
    -o IdentityFile=\"pkcs11:token=segfault\" somehost exit 5
r=$?
if [ $r -eq 139 ]; then
	fail "ssh connect with missing provider_id from configuration option" \
	    "crashed (exit code $r)"
fi


trace "SSH Agent can work with PKCS#11 URI"
trace "start the agent"
eval `${SSHAGENT} -s -P "${OBJ}/*"` > /dev/null

r=$?
if [ $r -ne 0 ]; then
	fail "could not start ssh-agent: exit code $r"
else
	trace "add whole provider to agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add failed with whole provider: exit code $r"
	fi

	trace " pkcs11 list via agent (all keys)"
	${SSHADD} -l > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -l failed with whole provider: exit code $r"
	fi

	trace " pkcs11 connect via agent (all keys)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "ssh connect failed with whole provider (exit code $r)"
	fi

	trace " remove pkcs11 keys (all keys)"
	${SSHADD} -d "pkcs11:?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -d failed with whole provider: exit code $r"
	fi

	trace "add only first key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=${ID1}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add failed with first key: exit code $r"
	fi

	trace " pkcs11 connect via agent (first key)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "ssh connect failed with first key (exit code $r)"
	fi

	trace " remove first pkcs11 key"
	${SSHADD} -d "pkcs11:id=${ID1}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -d failed with first key: exit code $r"
	fi

	trace "add only second key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=${ID2}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add failed with second key: exit code $r"
	fi

	trace " pkcs11 connect via agent (second key should fail)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -eq 5 ]; then
		fail "ssh connect passed without key (should fail)"
	fi

	trace "add also the first key to the agent"
	echo ${TEST_SSH_PIN} | notty ${SSHADD} \
	    "pkcs11:id=${ID1}?module-path=${TEST_SSH_PKCS11}" > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add failed with first key: exit code $r"
	fi

	trace " remove second pkcs11 key"
	${SSHADD} -d "pkcs11:id=${ID2}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -d failed with second key: exit code $r"
	fi

	trace " remove already-removed pkcs11 key should fail"
	${SSHADD} -d "pkcs11:id=${ID2}?module-path=${TEST_SSH_PKCS11}" \
	    > /dev/null 2>&1
	r=$?
	if [ $r -eq 0 ]; then
		fail "ssh-add -d passed with non-existing key (should fail)"
	fi

	trace " pkcs11 connect via agent (the first key should be still usable)"
	${SSH} -F $OBJ/ssh_proxy somehost exit 5
	r=$?
	if [ $r -ne 5 ]; then
		fail "ssh connect failed with first key (after removing second): exit code $r"
	fi

	trace "kill agent"
	${SSHAGENT} -k > /dev/null
fi

rm -rf $OBJ/.tokens $OBJ/token_keys
