/* $OpenBSD: ssh-pkcs11.c,v 1.26 2018/02/07 02:06:51 jsing Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#ifdef ENABLE_PKCS11

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <stdarg.h>
#include <stdio.h>

#include <string.h>
#include <dlfcn.h>

#include "openbsd-compat/sys-queue.h"
#include "openbsd-compat/openssl-compat.h"

#include <openssl/x509.h>
#include <openssl/rsa.h>
#ifdef OPENSSL_HAS_ECC
#include <openssl/ecdsa.h>
#if ((defined(LIBRESSL_VERSION_NUMBER) && \
	(LIBRESSL_VERSION_NUMBER >= 0x20010002L))) || \
	(defined(ECDSA_F_ECDSA_METHOD_NEW)) || \
	(OPENSSL_VERSION_NUMBER >= 0x00010100L)
#define ENABLE_PKCS11_ECDSA 1
#endif
#endif

#define CRYPTOKI_COMPAT
#include "pkcs11.h"

#include "log.h"
#include "misc.h"
#include "sshkey.h"
#include "ssh-pkcs11.h"
#include "xmalloc.h"

struct pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	int			logged_in;
};

struct pkcs11_module {
	char			*module_path;
	void			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	struct pkcs11_slotinfo	*slotinfo;
	int			valid;
	int			refcount;
};

struct pkcs11_provider {
	char			*name;
	struct pkcs11_module	*module; /* can be shared between various providers */
	int			refcount;
	int			valid;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

struct pkcs11_key {
	struct pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	CK_ULONG		key_type;
	int			(*orig_finish)(RSA *rsa);
	RSA_METHOD		*rsa_method;
	char			*keyid;
	int			keyid_len;
	char			*label;
};

int pkcs11_interactive = 0;
#ifdef ENABLE_PKCS11_ECDSA
static int pkcs11_key_idx = -1;
#endif /* ENABLE_PKCS11_ECDSA */

/*
 * This can't be in the ssh-pkcs11-uri, becase we can not depend on
 * PKCS#11 structures in ssh-agent (using client-helper communication)
 */
int
pkcs11_uri_write(const struct sshkey *key, FILE *f)
{
	char *p = NULL;
	struct pkcs11_uri uri;
	struct pkcs11_key *k11;

	/* sanity - is it a RSA key with associated app_data? */
	if (key->type != KEY_RSA ||
	    (k11 = RSA_get_app_data(key->rsa)) == NULL)
		return -1;

	/* omit type -- we are looking for private-public or private-certificate pairs */
	uri.id = k11->keyid;
	uri.id_len = k11->keyid_len;
	uri.token = k11->provider->module->slotinfo[k11->slotidx].token.label;
	uri.object = k11->label;
	uri.module_path = k11->provider->module->module_path;
	uri.lib_manuf = k11->provider->module->info.manufacturerID;
	uri.manuf = k11->provider->module->slotinfo[k11->slotidx].token.manufacturerID;

	p = pkcs11_uri_get(&uri);
	/* do not cleanup -- we do not allocate here, only reference */
	if (p == NULL)
		return -1;

	fprintf(f, " %s", p);
	free(p);
	return 0;
}

int
pkcs11_init(int interactive)
{
	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	return (0);
}

/*
 * finalize a provider shared libarary, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actuall freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
static void
pkcs11_module_finalize(struct pkcs11_module *m)
{
	CK_RV rv;
	CK_ULONG i;

	debug("%s: %p refcount %d valid %d", __func__,
	    m, m->refcount, m->valid);
	if (!m->valid)
		return;
	for (i = 0; i < m->nslots; i++) {
		if (m->slotinfo[i].session &&
		    (rv = m->function_list->C_CloseSession(
		    m->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	if ((rv = m->function_list->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	m->valid = 0;
	m->function_list = NULL;
	dlclose(m->handle);
}

/*
 * remove a reference to the pkcs11 module.
 * called when a provider is unregistered.
 */
static void
pkcs11_module_unref(struct pkcs11_module *m)
{
	debug("%s: %p refcount %d", __func__, m, m->refcount);
	if (--m->refcount <= 0) {
		pkcs11_module_finalize(m);
		if (m->valid)
			error("%s: %p still valid", __func__, m);
		free(m->slotlist);
		free(m->slotinfo);
		free(m->module_path);
		free(m);
	}
}

/*
 * finalize a provider shared libarary, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actuall freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
static void
pkcs11_provider_finalize(struct pkcs11_provider *p)
{
	debug("%s: %p refcount %d valid %d", __func__,
	    p, p->refcount, p->valid);
	if (!p->valid)
		return;
	pkcs11_module_unref(p->module);
	p->module = NULL;
	p->valid = 0;
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
static void
pkcs11_provider_unref(struct pkcs11_provider *p)
{
	debug("%s: %p refcount %d", __func__, p, p->refcount);
	if (--p->refcount <= 0) {
		if (p->module)
			pkcs11_module_unref(p->module);
		free(p->name);
		free(p);
	}
}

/* unregister all providers, keys might still point to the providers */
void
pkcs11_terminate(void)
{
	struct pkcs11_provider *p;

	while ((p = TAILQ_FIRST(&pkcs11_providers)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/* lookup provider by module path */
static struct pkcs11_module *
pkcs11_provider_lookup_module(char *module_path)
{
	struct pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check %p %s (%s)", p, p->name, p->module->module_path);
		if (!strcmp(module_path, p->module->module_path))
			return (p->module);
	}
	return (NULL);
}

/* lookup provider by name */
static struct pkcs11_provider *
pkcs11_provider_lookup(char *provider_id)
{
	struct pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check %p %s", p, p->name);
		if (!strcmp(provider_id, p->name))
			return (p);
	}
	return (NULL);
}

int pkcs11_del_provider_by_uri(struct pkcs11_uri *);

/* unregister provider by name */
int
pkcs11_del_provider(char *provider_id)
{
	int rv;
	struct pkcs11_uri *uri;

	debug("%s: called, provider_id = %s", __func__, provider_id);

	uri = pkcs11_uri_init();
	if (uri == NULL)
		fatal("Failed to init PCKS#11 URI");

	if (strlen(provider_id) >= strlen(PKCS11_URI_SCHEME) &&
	    strncmp(provider_id, PKCS11_URI_SCHEME, strlen(PKCS11_URI_SCHEME)) == 0) {
		if (pkcs11_uri_parse(provider_id, uri) != 0)
			fatal("Failed to parse PKCS#11 URI");
	} else {
		uri->module_path = strdup(provider_id);
	}

	rv = pkcs11_del_provider_by_uri(uri);
	pkcs11_uri_cleanup(uri);
	return rv;
}

/* unregister provider by PKCS#11 URI */
int
pkcs11_del_provider_by_uri(struct pkcs11_uri *uri)
{
	struct pkcs11_provider *p;
	int rv = -1;
	char *provider_uri = pkcs11_uri_get(uri);

	debug3("%s(%s): called", __func__, provider_uri);

	if ((p = pkcs11_provider_lookup(provider_uri)) != NULL) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		rv = 0;
	}
	free(provider_uri);
	return rv;
}

/* openssl callback for freeing an RSA key */
static int
pkcs11_rsa_finish(RSA *rsa)
{
	struct pkcs11_key	*k11;
	int rv = -1;

	if ((k11 = RSA_get_app_data(rsa)) != NULL) {
		if (k11->orig_finish)
			rv = k11->orig_finish(rsa);
		if (k11->provider)
			pkcs11_provider_unref(k11->provider);
		RSA_meth_free(k11->rsa_method);
		free(k11->keyid);
		free(k11->label);
		free(k11);
	}
	return (rv);
}

/* find a single 'obj' for given attributes */
static int
pkcs11_find(struct pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	int			ret = -1;

	f = p->module->function_list;
	session = p->module->slotinfo[slotidx].session;
	if ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		return (-1);
	}
	if ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} else
		ret = 0;
	if ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	return (ret);
}

int pkcs11_login(struct pkcs11_key *k11, CK_FUNCTION_LIST *f, struct pkcs11_slotinfo *si) {
	char			*pin = NULL, prompt[1024];
	CK_RV			rv;
	if ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		if (!pkcs11_interactive) {
			error("need pin entry%s", (si->token.flags &
			    CKF_PROTECTED_AUTHENTICATION_PATH) ?
			    " on reader keypad" : "");
			return (-1);
		}
		if (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
			verbose("Deferring PIN entry to reader keypad.");
		else {
			snprintf(prompt, sizeof(prompt),
			    "Enter PIN for '%s': ", si->token.label);
			pin = read_passphrase(prompt, RP_ALLOW_EOF);
			if (pin == NULL)
				return (-1);	/* bail out */
		}
		rv = f->C_Login(si->session, CKU_USER, (u_char *)pin,
		    (pin != NULL) ? strlen(pin) : 0);
		if (pin != NULL) {
			explicit_bzero(pin, strlen(pin));
			free(pin);
		}
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			return (-1);
		}
		si->logged_in = 1;
	}
	return 0;
}

/* openssl callback doing the actual signing operation */
static int
pkcs11_rsa_private_encrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_OBJECT_CLASS	private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL		true_val = CK_TRUE;
	CK_MECHANISM		mech = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};
	CK_ATTRIBUTE		key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};
	int			rval = -1;

	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

	if ((k11 = RSA_get_app_data(rsa)) == NULL) {
		error("RSA_get_app_data failed for rsa %p", rsa);
		return (-1);
	}
	if (!k11->provider || !k11->provider->valid || !k11->provider->module
	    || !k11->provider->module->valid) {
		error("no pkcs11 (valid) provider for rsa %p", rsa);
		return (-1);
	}
	f = k11->provider->module->function_list;
	si = &k11->provider->module->slotinfo[k11->slotidx];
	if(pkcs11_login(k11, f, si)) {
		return (-1);
	}
	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;
	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, &obj) < 0) {
		error("cannot find private key");
	} else if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
	} else {
		/* XXX handle CKR_BUFFER_TOO_SMALL */
		tlen = RSA_size(rsa);
		rv = f->C_Sign(si->session, (CK_BYTE *)from, flen, to, &tlen);
		if (rv == CKR_OK) 
			rval = tlen;
		else 
			error("C_Sign failed: %lu", rv);
	}
	return (rval);
}

static int
pkcs11_rsa_private_decrypt(int flen, const u_char *from, u_char *to, RSA *rsa,
    int padding)
{
	return (-1);
}

/* redirect private key operations for rsa key to pkcs11 token */
static int
pkcs11_rsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, CK_ATTRIBUTE *label_attrib, RSA *rsa)
{
	struct pkcs11_key	*k11;
	const RSA_METHOD	*def = RSA_get_default_method();

	k11 = xcalloc(1, sizeof(*k11));
	k11->key_type = CKK_RSA;
	k11->provider = provider;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}
	if (label_attrib->ulValueLen > 0 ) {
		k11->label = xmalloc(label_attrib->ulValueLen+1);
		memcpy(k11->label, label_attrib->pValue, label_attrib->ulValueLen);
		k11->label[label_attrib->ulValueLen] = 0;
	}
	k11->rsa_method = RSA_meth_dup(def);
	if (k11->rsa_method == NULL)
		fatal("%s: RSA_meth_dup failed", __func__);
	k11->orig_finish = RSA_meth_get_finish(def);
	if (!RSA_meth_set1_name(k11->rsa_method, "pkcs11") ||
	    !RSA_meth_set_priv_enc(k11->rsa_method,
	    pkcs11_rsa_private_encrypt) ||
	    !RSA_meth_set_priv_dec(k11->rsa_method,
	    pkcs11_rsa_private_decrypt) ||
	    !RSA_meth_set_finish(k11->rsa_method, pkcs11_rsa_finish))
		fatal("%s: setup pkcs11 method failed", __func__);
	RSA_set_method(rsa, k11->rsa_method);
	RSA_set_app_data(rsa, k11);
	return (0);
}

#ifdef ENABLE_PKCS11_ECDSA
static ECDSA_SIG *pkcs11_ecdsa_sign(const unsigned char *dgst, int dgst_len,
                                    const BIGNUM *inv, const BIGNUM *rp,
                                    EC_KEY *ecdsa) {
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		tlen = 0;
	CK_RV			rv;
	CK_OBJECT_CLASS	private_key_class = CKO_PRIVATE_KEY;
	CK_BBOOL		true_val = CK_TRUE;
	CK_MECHANISM		mech = {
		CKM_ECDSA, NULL_PTR, 0
	};
	CK_ATTRIBUTE		key_filter[] = {
		{CKA_CLASS, NULL, sizeof(private_key_class) },
		{CKA_ID, NULL, 0},
		{CKA_SIGN, NULL, sizeof(true_val) }
	};
	ECDSA_SIG  		*rval = NULL;
	key_filter[0].pValue = &private_key_class;
	key_filter[2].pValue = &true_val;

 #if (OPENSSL_VERSION_NUMBER >= 0x00010100L)
	if ((k11 = (struct pkcs11_key *)EC_KEY_get_ex_data(ecdsa, pkcs11_key_idx)) == NULL) {
		error("EC_KEY_get_ex_data failed for ecdsa %p", ecdsa);
 #else
	if ((k11 = (struct pkcs11_key *)ECDSA_get_ex_data(ecdsa, pkcs11_key_idx)) == NULL) {
		error("ECDSA_get_ex_data failed for ecdsa %p", ecdsa);
 #endif
		return NULL;
	}
	if (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider for ecdsa %p", ecdsa);
		return NULL;
	}
	f = k11->provider->module->function_list;
	si = &k11->provider->module->slotinfo[k11->slotidx];
	if(pkcs11_login(k11, f, si)) {
		return NULL;
	}
	key_filter[1].pValue = k11->keyid;
	key_filter[1].ulValueLen = k11->keyid_len;
	/* try to find object w/CKA_SIGN first, retry w/o */
	if (pkcs11_find(k11->provider, k11->slotidx, key_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, key_filter, 2, &obj) < 0) {
		error("cannot find private key");
	} else if ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
	} else {
		CK_BYTE_PTR buf = NULL;
		BIGNUM *r = NULL, *s = NULL;
		int nlen;
		/* Make a call to C_Sign to find out the size of the signature */
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, NULL, &tlen);
		if (rv != CKR_OK) {
			error("C_Sign failed: %lu", rv);
			return NULL;
		}
		if ((buf = xmalloc(tlen)) == NULL) {
			error("failure to allocate signature buffer");
			return NULL;
		}
		rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, buf, &tlen);
		if (rv != CKR_OK) {
			error("C_Sign failed: %lu", rv);
		}

		if ((rval = ECDSA_SIG_new()) == NULL ||
		    (r = BN_new()) == NULL ||
		    (s = BN_new()) == NULL) {
			error("failure to allocate ECDSA signature");
		} else {
			/*
			 * ECDSA signature is 2 large integers of same size returned
			 * concatenated by PKCS#11, we separate them to create an
			 * ECDSA_SIG for OpenSSL.
			 */
			nlen = tlen / 2;
			BN_bin2bn(&buf[0], nlen, r);
			BN_bin2bn(&buf[nlen], nlen, s);
			ECDSA_SIG_set0(rval, r, s);
		}
		free(buf);
	}
	return (rval);
}

#if (OPENSSL_VERSION_NUMBER >= 0x00010100L)
static EC_KEY_METHOD *get_pkcs11_ecdsa_method(void) {
	static EC_KEY_METHOD *pkcs11_ecdsa_method = NULL;
	if(pkcs11_key_idx == -1) {
		pkcs11_key_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if (pkcs11_ecdsa_method == NULL) {
		const EC_KEY_METHOD *def = EC_KEY_get_default_method();
		pkcs11_ecdsa_method = EC_KEY_METHOD_new(def);
		EC_KEY_METHOD_set_sign(pkcs11_ecdsa_method, NULL, NULL, pkcs11_ecdsa_sign);
	}
#else
static ECDSA_METHOD *get_pkcs11_ecdsa_method(void) {
	static ECDSA_METHOD *pkcs11_ecdsa_method = NULL;
	if(pkcs11_key_idx == -1) {
		pkcs11_key_idx = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	}
	if(pkcs11_ecdsa_method == NULL) {
		const ECDSA_METHOD *def = ECDSA_get_default_method();
 #ifdef ECDSA_F_ECDSA_METHOD_NEW
		pkcs11_ecdsa_method = ECDSA_METHOD_new((ECDSA_METHOD *)def);
		ECDSA_METHOD_set_name(pkcs11_ecdsa_method, "pkcs11");
		ECDSA_METHOD_set_sign(pkcs11_ecdsa_method, pkcs11_ecdsa_sign);
 #else
		pkcs11_ecdsa_method = xcalloc(1, sizeof(*pkcs11_ecdsa_method));
		memcpy(pkcs11_ecdsa_method, def, sizeof(*pkcs11_ecdsa_method));
		pkcs11_ecdsa_method->name = "pkcs11";
		pkcs11_ecdsa_method->ecdsa_do_sign = pkcs11_ecdsa_sign;
 #endif
	}
#endif
	return pkcs11_ecdsa_method;
}

static int
pkcs11_ecdsa_wrap(struct pkcs11_provider *provider, CK_ULONG slotidx,
                  CK_ATTRIBUTE *keyid_attrib, CK_ATTRIBUTE *label_attrib, EC_KEY *ecdsa)
{
	struct pkcs11_key *k11;
	k11 = xcalloc(1, sizeof(*k11));
	k11->key_type = CKK_EC;
	k11->provider = provider;
	provider->refcount++; /* provider referenced by ECDSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ulValueLen;
	if (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->pValue, k11->keyid_len);
	}
	if (label_attrib->ulValueLen > 0 ) {
		k11->label = xmalloc(label_attrib->ulValueLen+1);
		memcpy(k11->label, label_attrib->pValue, label_attrib->ulValueLen);
		k11->label[label_attrib->ulValueLen] = 0;
	}
 #if (OPENSSL_VERSION_NUMBER >= 0x00010100L)
	EC_KEY_set_method(ecdsa, get_pkcs11_ecdsa_method());
	EC_KEY_set_ex_data(ecdsa, pkcs11_key_idx, k11);
 #else
	ECDSA_set_method(ecdsa, get_pkcs11_ecdsa_method());
	ECDSA_set_ex_data(ecdsa, pkcs11_key_idx, k11);
 #endif
	return (0);
}
#endif /* ENABLE_PKCS11_ECDSA */

int pkcs11_del_key(struct sshkey *key) {
#ifdef ENABLE_PKCS11_ECDSA
	if(key->type == KEY_ECDSA) {
		struct pkcs11_key *k11 = (struct pkcs11_key *)
 #if (OPENSSL_VERSION_NUMBER >= 0x00010100L)
			EC_KEY_get_ex_data(key->ecdsa, pkcs11_key_idx);
 #else
			ECDSA_get_ex_data(key->ecdsa, pkcs11_key_idx);
 #endif
		if (k11 == NULL) {
			error("EC_KEY_get_ex_data failed for ecdsa %p", key->ecdsa);
		} else {
			if (k11->provider)
				pkcs11_provider_unref(k11->provider);
			free(k11->keyid);
			free(k11);
		}
	}
#endif /* ENABLE_PKCS11_ECDSA */
	sshkey_free(key);
	return (0);
}

/* remove trailing spaces */
static void
rmspace(u_char *buf, size_t len)
{
	size_t i;

	if (!len)
		return;
	for (i = len - 1;  i > 0; i--)
		if (i == len - 1 || buf[i] == ' ')
			buf[i] = '\0';
		else
			break;
}

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
static int
pkcs11_open_session(struct pkcs11_provider *p, CK_ULONG slotidx, char *pin)
{
	CK_RV			rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	int			login_required;

	f = p->module->function_list;
	login_required = p->module->slotinfo[slotidx].token.flags & CKF_LOGIN_REQUIRED;
	if (pin && login_required && !strlen(pin)) {
		error("pin required");
		return (-1);
	}
	if ((rv = f->C_OpenSession(p->module->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, NULL, NULL, &session))
	    != CKR_OK) {
		error("C_OpenSession failed for slot %lu: %lu", slotidx, rv);
		return (-1);
	}
	if (login_required && pin) {
		rv = f->C_Login(session, CKU_USER,
		    (u_char *)pin, strlen(pin));
		if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			if ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			return (-1);
		}
		p->module->slotinfo[slotidx].logged_in = 1;
	}
	p->module->slotinfo[slotidx].session = session;
	return (0);
}

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
static int pkcs11_fetch_keys_filter(struct pkcs11_provider *, CK_ULONG,
    CK_ATTRIBUTE [], size_t, CK_ATTRIBUTE [3], struct sshkey ***, int *)
	__attribute__((__bounded__(__minbytes__,4, 3 * sizeof(CK_ATTRIBUTE))));

static int
pkcs11_fetch_keys(struct pkcs11_provider *p, CK_ULONG slotidx,
    struct sshkey ***keysp, int *nkeys, struct pkcs11_uri *uri)
{
	size_t filter_size = 2;
	CK_KEY_TYPE pubkey_type = CKK_RSA;
	CK_OBJECT_CLASS	pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS	cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE		pubkey_filter[] = {
		{ CKA_CLASS, NULL, sizeof(pubkey_class) },
		{ CKA_KEY_TYPE, NULL, sizeof(pubkey_type) },
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 }
	};
	CK_ATTRIBUTE		cert_filter[] = {
		{ CKA_CLASS, NULL, sizeof(cert_class) },
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 }
	};
	CK_ATTRIBUTE		pubkey_attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 }
	};
	CK_ATTRIBUTE		cert_attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_SUBJECT, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};
#ifdef ENABLE_PKCS11_ECDSA
	CK_KEY_TYPE	        ecdsa_type = CKK_EC;
	CK_ATTRIBUTE		ecdsa_filter[] = {
		{ CKA_CLASS, NULL, sizeof(pubkey_class) },
		{ CKA_KEY_TYPE, NULL, sizeof(ecdsa_type) },
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 }
	};
	CK_ATTRIBUTE		ecdsa_attribs[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_EC_POINT, NULL, 0 }
	};
	ecdsa_filter[0].pValue = &pubkey_class;
	ecdsa_filter[1].pValue = &ecdsa_type;
#endif /* ENABLE_PKCS11_ECDSA */
	pubkey_filter[0].pValue = &pubkey_class;
	pubkey_filter[1].pValue = &pubkey_type;
	cert_filter[0].pValue = &cert_class;

	if (uri->id != NULL) {
		pubkey_filter[filter_size].pValue = uri->id;
		pubkey_filter[filter_size].ulValueLen = uri->id_len;
#ifdef ENABLE_PKCS11_ECDSA
		ecdsa_filter[filter_size].pValue = uri->id;
		ecdsa_filter[filter_size].ulValueLen = uri->id_len;
#endif /* ENABLE_PKCS11_ECDSA */
		cert_filter[filter_size-1].pValue = uri->id;
		cert_filter[filter_size-1].ulValueLen = uri->id_len;
		filter_size++;
	}
	if (uri->object != NULL) {
		pubkey_filter[filter_size].pValue = uri->object;
		pubkey_filter[filter_size].ulValueLen = strlen(uri->object);
		pubkey_filter[filter_size].type = CKA_LABEL;
#ifdef ENABLE_PKCS11_ECDSA
		ecdsa_filter[filter_size].pValue = uri->object;
		ecdsa_filter[filter_size].ulValueLen = strlen(uri->object);
		ecdsa_filter[filter_size].type = CKA_LABEL;
#endif /* ENABLE_PKCS11_ECDSA */
		cert_filter[filter_size-1].pValue = uri->object;
		cert_filter[filter_size-1].ulValueLen = strlen(uri->object);
		cert_filter[filter_size-1].type = CKA_LABEL;
		filter_size++;
	}

	if (pkcs11_fetch_keys_filter(p, slotidx, pubkey_filter, filter_size,
	    pubkey_attribs, keysp, nkeys) < 0 ||
#ifdef ENABLE_PKCS11_ECDSA
	    pkcs11_fetch_keys_filter(p, slotidx, ecdsa_filter, filter_size,
	    ecdsa_attribs, keysp, nkeys) < 0||
#endif /* ENABLE_PKCS11_ECDSA */
	    pkcs11_fetch_keys_filter(p, slotidx, cert_filter, filter_size - 1,
	    cert_attribs, keysp, nkeys) < 0)
		return (-1);
	if (*nkeys == 0) {
		/* Try once more without the label filter */
		filter_size--;
		if (pkcs11_fetch_keys_filter(p, slotidx, pubkey_filter, filter_size,
		    pubkey_attribs, keysp, nkeys) < 0 ||
#ifdef ENABLE_PKCS11_ECDSA
		    pkcs11_fetch_keys_filter(p, slotidx, ecdsa_filter, filter_size,
		    ecdsa_attribs, keysp, nkeys) < 0||
#endif /* ENABLE_PKCS11_ECDSA */
		    pkcs11_fetch_keys_filter(p, slotidx, cert_filter, filter_size - 1,
		    cert_attribs, keysp, nkeys) < 0)
	 		return (-1);
	}
	return (0);
}

static int
pkcs11_key_included(struct sshkey ***keysp, int *nkeys, struct sshkey *key)
{
	int i;

	for (i = 0; i < *nkeys; i++)
		if (sshkey_equal(key, (*keysp)[i]))
			return (1);
	return (0);
}

static int
have_rsa_key(const RSA *rsa)
{
	const BIGNUM *rsa_n, *rsa_e;

	RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
	return rsa_n != NULL && rsa_e != NULL;
}

static int
pkcs11_fetch_keys_filter(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_ATTRIBUTE filter[], size_t filter_size, CK_ATTRIBUTE attribs[4],
    struct sshkey ***keysp, int *nkeys)
{
	struct sshkey		*key = NULL;
	RSA			*rsa;
#ifdef ENABLE_PKCS11_ECDSA
	EC_KEY			*ecdsa;
#else
	void			*ecdsa;
#endif /* ENABLE_PKCS11_ECDSA */
	X509 			*x509;
	EVP_PKEY		*evp = NULL;
	int			i;
	int			nattribs = 4;
	const u_char		*cp;
	CK_RV			rv;
	CK_OBJECT_HANDLE	obj;
	CK_ULONG		nfound;
	CK_SESSION_HANDLE	session;
	CK_FUNCTION_LIST	*f;

	f = p->module->function_list;
	session = p->module->slotinfo[slotidx].session;
	/* setup a filter the looks for public keys */
	if ((rv = f->C_FindObjectsInit(session, filter, filter_size)) != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		return (-1);
	}
	while (1) {
		for (i = 0; i < nattribs; i++) {
			attribs[i].pValue = NULL;
			attribs[i].ulValueLen = 0;
		}
		if ((rv = f->C_FindObjects(session, &obj, 1, &nfound)) != CKR_OK
		    || nfound == 0)
			break;
		/* found a key, so figure out size of the attributes */
		if ((rv = f->C_GetAttributeValue(session, obj, attribs, nattribs))
		    != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			continue;
		}
		/*
		 * Allow CKA_ID (always first attribute) and CKA_LABEL (second)
		 * to be empty, but ensure that none of the others are zero length.
		 * XXX assumes CKA_ID is always first.
		 */
		if (attribs[2].ulValueLen == 0 ||
		    attribs[3].ulValueLen == 0) {
			continue;
		}
		/* allocate buffers for attributes */
		for (i = 0; i < nattribs; i++) {
			if (attribs[i].ulValueLen > 0) {
				attribs[i].pValue = xmalloc(
				    attribs[i].ulValueLen);
			}
		}

		/*
		 * retrieve ID, label, modulus and public exponent of RSA key,
		 * or ID, label, subject and value for certificates.
		 */
		rsa = NULL;
#ifdef ENABLE_PKCS11_ECDSA
		ecdsa = NULL;
#endif /* ENABLE_PKCS11_ECDSA */
		if ((rv = f->C_GetAttributeValue(session, obj, attribs, nattribs))
		    != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
		} else if (attribs[2].type == CKA_MODULUS ) {
			if ((rsa = RSA_new()) == NULL) {
				error("RSA_new failed");
			} else {
				BIGNUM *rsa_n, *rsa_e;

				rsa_n = BN_bin2bn(attribs[2].pValue,
				    attribs[2].ulValueLen, NULL);
				rsa_e = BN_bin2bn(attribs[3].pValue,
				    attribs[3].ulValueLen, NULL);
				if (rsa_n != NULL && rsa_e != NULL) {
					if (!RSA_set0_key(rsa,
					    rsa_n, rsa_e, NULL))
						fatal("%s: set key", __func__);
					rsa_n = rsa_e = NULL; /* transferred */
				}
				BN_free(rsa_n);
				BN_free(rsa_e);
			}
#ifdef ENABLE_PKCS11_ECDSA
		} else if (attribs[2].type == CKA_EC_PARAMS ) {
			if ((ecdsa = EC_KEY_new()) == NULL) {
				error("EC_KEY_new failed");
			} else {
				const unsigned char *ptr1 = attribs[2].pValue;
				const unsigned char *ptr2 = attribs[3].pValue;
				CK_ULONG len1 = attribs[2].ulValueLen;
				CK_ULONG len2 = attribs[3].ulValueLen;
				ASN1_OCTET_STRING *point = NULL;

				/*
				 * CKA_EC_PARAMS contains the curve parameters of the key
				 * either referenced as an OID or directly with all values.
				 * CKA_EC_POINT contains the point (public key) on the curve.
				 * The point is should be returned inside a DER-encoded
				 * ASN.1 OCTET STRING value (but some implementation).
				 */
				if ((point = d2i_ASN1_OCTET_STRING(NULL, &ptr2, len2))) {
					/* Pointing to OCTET STRING content */
					ptr2 = point->data;
					len2 = point->length;
				} else {
					/* No OCTET STRING */
					ptr2 = attribs[3].pValue;
				}

				if((d2i_ECParameters(&ecdsa, &ptr1, len1) == NULL) ||
				   (o2i_ECPublicKey(&ecdsa, &ptr2, len2) == NULL)) {
					EC_KEY_free(ecdsa);
					ecdsa = NULL;
					error("EC public key parsing failed");
				}

				if(point) {
					ASN1_OCTET_STRING_free(point);
				}
			}
#endif /* ENABLE_PKCS11_ECDSA */
		} else {
			cp = attribs[3].pValue;
			if ((x509 = X509_new()) == NULL) {
				error("X509_new failed");
			} else if (d2i_X509(&x509, &cp, attribs[3].ulValueLen)
			    == NULL) {
				error("d2i_X509 failed");
			} else if ((evp = X509_get_pubkey(x509)) == NULL) {
				debug("X509_get_pubkey failed");
			} else {
				switch (EVP_PKEY_base_id(evp)) {
				case EVP_PKEY_RSA:
					if (EVP_PKEY_get0_RSA(evp) == NULL)
						debug("Missing RSA key");
					else if ((rsa = RSAPublicKey_dup(
					    EVP_PKEY_get0_RSA(evp))) == NULL)
						error("RSAPublicKey_dup failed");
					break;
				case EVP_PKEY_EC:
					if (EVP_PKEY_get0_EC_KEY(evp) == NULL)
						debug("Missing ECDSA key");
					else if ((ecdsa = EC_KEY_dup(
					    EVP_PKEY_get0_EC_KEY(evp))) == NULL)
						error("EC_KEY_dup failed");
					break;
				default:
					debug("not a RSA or ECDSA key");
					break;
				}
			}
			X509_free(x509);
			EVP_PKEY_free(evp);
		}
		if (rsa && have_rsa_key(rsa) &&
		    pkcs11_rsa_wrap(p, slotidx, &attribs[0], &attribs[1], rsa) == 0) {
			if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
				fatal("sshkey_new failed");
			key->rsa = rsa;
			key->type = KEY_RSA;
			key->flags |= SSHKEY_FLAG_EXT;
#ifdef ENABLE_PKCS11_ECDSA
		} else if (ecdsa &&
		    pkcs11_ecdsa_wrap(p, slotidx, &attribs[0], &attribs[1], ecdsa) == 0) {
			if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
				fatal("sshkey_new failed");
			key->ecdsa = ecdsa;
			key->ecdsa_nid = sshkey_ecdsa_key_to_nid(key->ecdsa);
			key->type = KEY_ECDSA;
			key->flags |= SSHKEY_FLAG_EXT;
#endif /* ENABLE_PKCS11_ECDSA */
		}
		if (key) {
			if (pkcs11_key_included(keysp, nkeys, key)) {
				sshkey_free(key);
			} else {
				/* expand key array and add key */
				*keysp = xrecallocarray(*keysp, *nkeys,
				    *nkeys + 1, sizeof(struct sshkey *));
				(*keysp)[*nkeys] = key;
				*nkeys = *nkeys + 1;
				debug("have %d keys", *nkeys);
			}
		} else if (rsa) {
			RSA_free(rsa);
#ifdef ENABLE_PKCS11_ECDSA
		} else if (ecdsa) {
			EC_KEY_free(ecdsa);
#endif /* ENABLE_PKCS11_ECDSA */
		}
		for (i = 0; i < nattribs; i++)
			free(attribs[i].pValue);
	}
	if ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	return (0);
}

/* register a new provider, fails if provider already exists */
int
pkcs11_add_provider(char *provider_id, char *pin, struct sshkey ***keyp)
{
	int rv;
	struct pkcs11_uri *uri;

	debug("%s: called, provider_id = %s", __func__, provider_id);

	uri = pkcs11_uri_init();
	if (uri == NULL)
		fatal("Failed to init PCKS#11 URI");

	if (strlen(provider_id) >= strlen(PKCS11_URI_SCHEME) &&
	    strncmp(provider_id, PKCS11_URI_SCHEME, strlen(PKCS11_URI_SCHEME)) == 0) {
		if (pkcs11_uri_parse(provider_id, uri) != 0)
			fatal("Failed to parse PKCS#11 URI");
	} else {
		uri->module_path = strdup(provider_id);
	}

	rv = pkcs11_add_provider_by_uri(uri, pin, keyp);
	pkcs11_uri_cleanup(uri);
	return rv;
}

struct pkcs11_provider *
pkcs11_provider_initialize(struct pkcs11_uri *uri)
{
	int need_finalize = 0;
	void *handle = NULL;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = NULL;
	CK_TOKEN_INFO *token;
	CK_ULONG i;
	char *provider_module = NULL;
	struct pkcs11_provider *p;
	struct pkcs11_module *m;

	/* if no provider specified, fallback to p11-kit */
	if (uri->module_path == NULL) {
#ifdef PKCS11_DEFAULT_PROVIDER
		provider_module = strdup(PKCS11_DEFAULT_PROVIDER);
#else
		error("%s: No module path provided", __func__);
		goto fail;
#endif
	} else
		provider_module = strdup(uri->module_path);

	p = xcalloc(1, sizeof(*p));
	p->name = pkcs11_uri_get(uri);

	if ((m = pkcs11_provider_lookup_module(provider_module)) != NULL
	    && m->valid) {
		debug("%s: provider module already initialized: %s",
		    __func__, provider_module);
		free(provider_module);
		/* Skip the initialization of PKCS#11 module */
		m->refcount++;
		p->module = m;
		p->valid = 1;
		TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
		p->refcount++;	/* add to provider list */
		return p;
	} else {
		m = xcalloc(1, sizeof(*m));
		p->module = m;
		m->refcount++;
	}

	/* open shared pkcs11-libarary */
	if ((handle = dlopen(provider_module, RTLD_NOW)) == NULL) {
		error("dlopen %s failed: %s", provider_module, dlerror());
		goto fail;
	}
	if ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == NULL) {
		error("dlsym(C_GetFunctionList) failed: %s", dlerror());
		goto fail;
	}
	m->handle = handle;
	/* setup the pkcs11 callbacks */
	if ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_module, rv);
		goto fail;
	}
	m->function_list = f;
	if ((rv = f->C_Initialize(NULL)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_module, rv);
		goto fail;
	}
	need_finalize = 1;
	if ((rv = f->C_GetInfo(&m->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_module, rv);
		goto fail;
	}
	rmspace(m->info.manufacturerID, sizeof(m->info.manufacturerID));
	if (uri->lib_manuf != NULL &&
	    strcmp(uri->lib_manuf, m->info.manufacturerID)) {
		debug("%s: Skipping provider %s not matching library_manufacturer",
		    __func__, m->info.manufacturerID);
		goto fail;
	}
	rmspace(m->info.libraryDescription, sizeof(m->info.libraryDescription));
	debug("provider %s: manufacturerID <%s> cryptokiVersion %d.%d"
	    " libraryDescription <%s> libraryVersion %d.%d",
	    provider_module,
	    m->info.manufacturerID,
	    m->info.cryptokiVersion.major,
	    m->info.cryptokiVersion.minor,
	    m->info.libraryDescription,
	    m->info.libraryVersion.major,
	    m->info.libraryVersion.minor);

	if ((rv = f->C_GetSlotList(CK_TRUE, NULL, &m->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		goto fail;
	}
	if (m->nslots == 0) {
		debug("%s: provider %s returned no slots", __func__,
		    provider_module);
		goto fail;
	}
	m->slotlist = xcalloc(m->nslots, sizeof(CK_SLOT_ID));
	if ((rv = f->C_GetSlotList(CK_TRUE, m->slotlist, &m->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_module, rv);
		goto fail;
	}
	m->slotinfo = xcalloc(m->nslots, sizeof(struct pkcs11_slotinfo));
	m->valid = 1;
	p->valid = 1;

	for (i = 0; i < m->nslots; i++) {
		token = &m->slotinfo[i].token;
		if ((rv = f->C_GetTokenInfo(m->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_module, (unsigned long)i, rv);
			continue;
		}
		if ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			continue;
		}
		rmspace(token->label, sizeof(token->label));
		rmspace(token->manufacturerID, sizeof(token->manufacturerID));
		rmspace(token->model, sizeof(token->model));
		rmspace(token->serialNumber, sizeof(token->serialNumber));
	}
	m->module_path = provider_module;
	provider_module = NULL;

	/* insert unconditionally -- remove if there will be no keys later */
	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */
	return p;

fail:
	if (need_finalize && (rv = f->C_Finalize(NULL)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_module, rv);
	free(provider_module);
	free(p);
	if (handle)
		dlclose(handle);
	return NULL;
}

int
pkcs11_add_provider_by_uri(struct pkcs11_uri *uri, char *pin, struct sshkey ***keyp)
{
	int nkeys;
	struct pkcs11_provider *p = NULL;
	CK_TOKEN_INFO *token;
	CK_ULONG i;
	char *provider_uri = pkcs11_uri_get(uri);

	debug("%s: called, provider_uri = %s", __func__, provider_uri);

	*keyp = NULL;
	if ((p = pkcs11_provider_initialize(uri)) == NULL) {
		debug("%s: failed to initialize provider: %s",
		    __func__, provider_uri);
		goto fail;
	}

	nkeys = 0;
	for (i = 0; i < p->module->nslots; i++) {
		token = &p->module->slotinfo[i].token;
		if ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2("%s: ignoring uninitialised token in "
			    "provider %s slot %lu", __func__,
			    provider_uri, (unsigned long)i);
			continue;
		}
		if (uri->token != NULL &&
		    strcmp(token->label, uri->token) != 0) {
			debug2("%s: ignoring token not matching label (%s) "
			    "specified by PKCS#11 URI in slot %lu", __func__,
			    token->label, (unsigned long)i);
			continue;
		}
		if (uri->manuf != NULL &&
		    strcmp(token->manufacturerID, uri->manuf) != 0) {
			debug2("%s: ignoring token not matching requrested "
			    "manufacturerID (%s) specified by PKCS#11 URI in "
			    "slot %lu", __func__,
			    token->manufacturerID, (unsigned long)i);
			continue;
		}
		debug("provider %s slot %lu: label <%s> manufacturerID <%s> "
		    "model <%s> serial <%s> flags 0x%lx",
		    provider_uri, (unsigned long)i,
		    token->label, token->manufacturerID, token->model,
		    token->serialNumber, token->flags);
		/* open session if not yet opened, login with pin
		 * and retrieve public keys */
		if ((p->module->slotinfo[i].session != 0) ||
		    pkcs11_open_session(p, i, pin) == 0)
			pkcs11_fetch_keys(p, i, keyp, &nkeys, uri);
	}
	if (nkeys > 0) {
		free(provider_uri);
		return (nkeys);
	}
	debug("%s: provider %s returned no keys", __func__, provider_uri);
	/* don't add the provider, since it does not have any keys */
fail:
	if (p) {
 		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_unref(p);
	}
	free(provider_uri);
	return (-1);
}

#else

int
pkcs11_init(int interactive)
{
	return (0);
}

void
pkcs11_terminate(void)
{
	return;
}

#endif /* ENABLE_PKCS11 */
