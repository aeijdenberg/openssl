/*
 * Written by Rob Stradling (rob@comodo.com) and Stephen Henson
 * (steve@openssl.org) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ct.h>
#include "ct_locl.h"

SCT_CTX *SCT_CTX_new(void)
{
    SCT_CTX *sctx = OPENSSL_malloc(sizeof(SCT_CTX));
    if (!sctx)
        CTerr(CT_F_SCT_CTX_NEW, ERR_R_MALLOC_FAILURE);
    else
        memset(sctx, 0, sizeof(SCT_CTX));
    return sctx;
}

void SCT_CTX_free(SCT_CTX * sctx)
{
    if (!sctx)
        return;
    if (sctx->pkey)
        EVP_PKEY_free(sctx->pkey);
    if (sctx->pkeyhash)
        OPENSSL_free(sctx->pkeyhash);
    if (sctx->ihash)
        OPENSSL_free(sctx->ihash);
    if (sctx->certder)
        OPENSSL_free(sctx->certder);
    if (sctx->preder)
        OPENSSL_free(sctx->preder);
    OPENSSL_free(sctx);
}

/* retrieve extension index checking for duplicates */
static int sct_get_ext(X509 *cert, int nid)
{
    int rv = X509_get_ext_by_NID(cert, nid, -1);
    if (rv >= 0 && X509_get_ext_by_NID(cert, nid, rv) >= 0)
        return -2;
    return rv;
}

/*
 * modify certificate by deleting extensions, copying issuer
 * and AKID if necessary.
 */
static int sct_cert_fixup(X509 *cert, X509 *presigner)
{
    int preidx, certidx;
    if (presigner == NULL)
        return 1;
    preidx = sct_get_ext(presigner, NID_authority_key_identifier);
    certidx = sct_get_ext(cert, NID_authority_key_identifier);
    /* Invalid certificate if duplicate */
    if (preidx == -2 || certidx == -2)
        return 0;
    /* AKID must be present in both certificate or absent in both */
    if (preidx >= 0 && certidx == -1)
        return 0;
    if (preidx == -1 && certidx >= 0)
        return 0;
    /* Copy issuer name */
    if (!X509_set_issuer_name(cert, X509_get_issuer_name(presigner)))
        return 0;
    if (preidx != -1) {
        /* Retrieve and copy AKID encoding */
        X509_EXTENSION *preext = X509_get_ext(presigner, preidx);
        X509_EXTENSION *certext = X509_get_ext(cert, certidx);
        ASN1_OCTET_STRING *preextdata;
        /* Should never happen */
        if (!preext || !certext)
            return 0;
        preextdata = X509_EXTENSION_get_data(preext);
        if (!preextdata || !X509_EXTENSION_set_data(certext, preextdata))
            return 0;
    }
    return 1;
}

int SCT_CTX_set1_cert(SCT_CTX * sctx, X509 *cert, X509 *presigner)
{
    unsigned char *certder = NULL, *preder = NULL;
    X509 *pretmp = NULL;
    int certderlen = 0, prederlen = 0;
    int idx = -1, idxp = -1;
    idxp = sct_get_ext(cert, NID_ct_precert_poison);
    /* Duplicate poison */
    if (idxp == -2)
        goto err;
    /* If no poison store encoding */
    if (idxp == -1) {
        /* If presigner must have poison */
        if (presigner)
            goto err;
        certderlen = i2d_X509(cert, &certder);
        if (certderlen < 0)
            goto err;
    }
    /* See if have precert scts extension */
    idx = X509_get_ext_by_NID(cert, NID_ct_precert_scts, -1);
    /* Duplicate scts */
    if (idx == -2)
        goto err;
    if (idx >= 0) {
        /* Can't have both poison and scts */
        if (idxp >= 0)
            goto err;
    } else
        idx = idxp;
    if (idx >= 0) {
        X509_EXTENSION *ext;
        /*
         * Take a copy of certificate so we don't modify passed version
         */
        pretmp = X509_dup(cert);
        if (!pretmp)
            goto err;
        ext = X509_delete_ext(pretmp, idx);
        X509_EXTENSION_free(ext);
        if (!sct_cert_fixup(pretmp, presigner))
            goto err;

        prederlen = i2d_re_X509_tbs(pretmp, &preder);
        if (prederlen <= 0)
            goto err;
    }

    if (pretmp)
        X509_free(pretmp);

    if (sctx->certder)
        OPENSSL_free(sctx->certder);
    sctx->certder = certder;
    sctx->certderlen = certderlen;

    if (sctx->preder)
        OPENSSL_free(sctx->preder);
    sctx->preder = preder;
    sctx->prederlen = prederlen;

    return 1;

 err:
    if (certder)
        OPENSSL_free(certder);
    if (preder)
        OPENSSL_free(preder);
    if (pretmp)
        X509_free(pretmp);
    return 0;
}

static int sct_set1_key_hash(unsigned char **phash, size_t *phashlen,
                             X509_PUBKEY *pkey)
{
    int ret = 0;
    unsigned char *md = NULL, *der = NULL;
    int derlen;
    unsigned int mdlen;
    if (!pkey)
        return 0;
    /* Reuse buffer if possible */
    if (*phash && *phashlen == SCT_V1_HASHLEN)
        md = *phash;
    else
        md = OPENSSL_malloc(SCT_V1_HASHLEN);

    if (md == NULL)
        goto err;

    /* Calculate key hash */
    derlen = i2d_X509_PUBKEY(pkey, &der);
    if (derlen <= 0)
        goto err;
    if (!EVP_Digest(der, derlen, md, &mdlen, EVP_sha256(), NULL))
        goto err;
    if (md != *phash) {
        OPENSSL_free(*phash);
        *phash = md;
        *phashlen = SCT_V1_HASHLEN;
    }
    md = NULL;
    ret = 1;
 err:
    if (md)
        OPENSSL_free(md);
    if (der)
        OPENSSL_free(der);
    return ret;
}

int SCT_CTX_set1_issuer(SCT_CTX * sctx, const X509 *issuer)
{
    return sct_set1_key_hash(&sctx->ihash, &sctx->ihashlen,
                             issuer->cert_info->key);
}

int SCT_CTX_set1_issuerpubkey(SCT_CTX * sctx, X509_PUBKEY *pubkey)
{
    return sct_set1_key_hash(&sctx->ihash, &sctx->ihashlen, pubkey);
}

int SCT_CTX_set1_pubkey(SCT_CTX * sctx, X509_PUBKEY *pubkey)
{
    EVP_PKEY *pkey;
    pkey = X509_PUBKEY_get(pubkey);
    if (!pkey)
        return 0;
    if (!sct_set1_key_hash(&sctx->pkeyhash, &sctx->pkeyhashlen, pubkey)) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    if (sctx->pkey)
        EVP_PKEY_free(sctx->pkey);
    sctx->pkey = pkey;
    return 1;
}
