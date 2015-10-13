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
#ifndef OPENSSL_NO_CT

# include <limits.h>
# include "internal/cryptlib.h"
# include <openssl/asn1.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/ct.h>
# include "../ssl/ssl_locl.h"

/*
 * Update encoding for SCT signature verification/generation to supplied
 * EVP_MD_CTX.
 */
static int sct_ctx_update(EVP_MD_CTX *ctx, const SCT_CTX * sctx,
                          const SCT *sct)
{
    unsigned char tmpbuf[12];
    unsigned char *p, *der;
    size_t derlen;
    /*
     * digitally-signed struct { (1 byte) Version sct_version; (1 byte)
     * SignatureType signature_type = certificate_timestamp; (8 bytes) uint64
     * timestamp; (2 bytes) LogEntryType entry_type; (? bytes)
     * select(entry_type) { case x509_entry: ASN.1Cert; case precert_entry:
     * PreCert; } signed_entry; (2 bytes + sct->extlen) CtExtensions
     * extensions;
     */

    if (sct->entry_type == UNSET_ENTRY)
        return 0;

    if (sct->entry_type == PRECERT_ENTRY && !sctx->ihash)
        return 0;

    p = tmpbuf;

    *p++ = sct->version;
    *p++ = 0;                   /* 0 = certificate_timestamp */
    l2n8(sct->timestamp, p);
    s2n(sct->entry_type, p);

    if (!EVP_VerifyUpdate(ctx, tmpbuf, p - tmpbuf))
        return 0;

    if (sct->entry_type == X509_ENTRY) {
        der = sctx->certder;
        derlen = sctx->certderlen;
    } else {                    /* entry_type == PRECERT_ENTRY: caller has
                                 * checked it is set */

        if (!EVP_VerifyUpdate(ctx, sctx->ihash, sctx->ihashlen))
            return 0;
        der = sctx->preder;
        derlen = sctx->prederlen;
    }

    /* If no encoding available fatal error */
    if (der == NULL)
        return 0;

    /* Include length first */
    p = tmpbuf;
    l2n3(derlen, p);

    if (!EVP_VerifyUpdate(ctx, tmpbuf, 3))
        return 0;
    if (!EVP_VerifyUpdate(ctx, der, derlen))
        return 0;

    /* Add any extensions */
    p = tmpbuf;
    s2n(sct->extlen, p);
    if (!EVP_VerifyUpdate(ctx, tmpbuf, 2))
        return 0;

    if (sct->extlen && !EVP_VerifyUpdate(ctx, sct->ext, sct->extlen))
        return 0;

    return 1;
}

int SCT_verify(const SCT_CTX * sctx, const SCT *sct)
{
    EVP_MD_CTX ctx;
    int ret = -1;
    if (!sct_check_format(sct) || !sctx->pkey
        || sct->entry_type == UNSET_ENTRY || (sct->entry_type == PRECERT_ENTRY
                                              && !sctx->ihash)) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_NOT_SET);
        return -1;
    } else if (sct->version != 0) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_UNSUPPORTED_VERSION);
        return 0;
    }
    if (sct->logidlen != sctx->pkeyhashlen ||
        memcmp(sct->logid, sctx->pkeyhash, sctx->pkeyhashlen)) {
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_LOG_ID_MISMATCH);
        return 0;
    }
    EVP_MD_CTX_init(&ctx);

    if (!EVP_VerifyInit(&ctx, EVP_sha256()))
        goto done;

    if (!sct_ctx_update(&ctx, sctx, sct))
        goto done;

    /* Verify signature */
    ret = EVP_VerifyFinal(&ctx, sct->sig, sct->siglen, sctx->pkey);
    /* If ret < 0 some other error: fall through without seting error */
    if (ret == 0)
        CTerr(CT_F_SCT_VERIFY, CT_R_SCT_INVALID_SIGNATURE);

 done:
    EVP_MD_CTX_cleanup(&ctx);
    return ret;
}

int SCT_verify_v1(SCT *sct, X509 *cert, X509 *preissuer,
                  X509_PUBKEY *log_pubkey, X509 *issuer_cert)
{
    int ret = 0;
    SCT_CTX *sctx = NULL;

    if (!sct || !cert || !log_pubkey
        || ((sct->entry_type == PRECERT_ENTRY) && !issuer_cert)) {
        CTerr(CT_F_SCT_VERIFY_V1, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    } else if (!sct_check_format(sct)) {
        CTerr(CT_F_SCT_VERIFY_V1, CT_R_SCT_NOT_SET);
        return -1;
    } else if (sct->version != 0) {
        CTerr(CT_F_SCT_VERIFY_V1, CT_R_SCT_UNSUPPORTED_VERSION);
        return 0;
    }

    sctx = SCT_CTX_new();
    if (!sctx)
        goto done;

    ret = SCT_CTX_set1_pubkey(sctx, log_pubkey);

    if (ret <= 0)
        goto done;

    ret = SCT_CTX_set1_cert(sctx, cert, preissuer);

    if (ret <= 0)
        goto done;

    if (sct->entry_type == PRECERT_ENTRY) {
        ret = SCT_CTX_set1_issuer(sctx, issuer_cert);
        if (ret <= 0)
            goto done;
    }

    ret = SCT_verify(sctx, sct);

 done:
    if (sctx)
        SCT_CTX_free(sctx);
    return ret;
}

#endif