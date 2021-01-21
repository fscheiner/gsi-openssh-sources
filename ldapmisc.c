
#include "ldapincludes.h"
#include "ldapmisc.h"

#ifndef HAVE_LDAP_GET_LDERRNO
int
ldap_get_lderrno (LDAP * ld, char **m, char **s)
{
#ifdef HAVE_LDAP_GET_OPTION
	int rc;
#endif
	int lderrno;

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
	if ((rc = ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &lderrno)) != LDAP_SUCCESS)
	    return rc;
#else
	lderrno = ld->ld_errno;
#endif

	if (s != NULL) {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_STRING)
		if ((rc = ldap_get_option (ld, LDAP_OPT_ERROR_STRING, s)) != LDAP_SUCCESS)
		    return rc;
#else
		*s = ld->ld_error;
#endif
	}

	if (m != NULL) {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_MATCHED_DN)
		if ((rc = ldap_get_option (ld, LDAP_OPT_MATCHED_DN, m)) != LDAP_SUCCESS)
		    return rc;
#else
		*m = ld->ld_matched;
#endif
	}

	return lderrno;
}
#endif

#ifndef HAVE_LDAP_SET_LDERRNO
int
ldap_set_lderrno (LDAP * ld, int lderrno, const char *m, const char *s)
{
#ifdef HAVE_LDAP_SET_OPTION
	int rc;
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
	if ((rc = ldap_set_option (ld, LDAP_OPT_ERROR_NUMBER, &lderrno)) != LDAP_SUCCESS)
	    return rc;
#else
	ld->ld_errno = lderrno;
#endif

	if (s != NULL) {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_ERROR_STRING)
		if ((rc = ldap_set_option (ld, LDAP_OPT_ERROR_STRING, s)) != LDAP_SUCCESS)
		    return rc;
#else
		ld->ld_error = s;
#endif
	}

	if (m != NULL) {
#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_MATCHED_DN)
		if ((rc = ldap_set_option (ld, LDAP_OPT_MATCHED_DN, m)) != LDAP_SUCCESS)
		    return rc;
#else
		ld->ld_matched = m;
#endif
	}

	return LDAP_SUCCESS;
}
#endif

