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
# include "ct_locl.h"
# include "../ssl/ssl_locl.h"

static int sct_base64_decode(const char *in, unsigned char **out)
{
    EVP_ENCODE_CTX ctx;
    int len = 0;
    unsigned char *outbuf;
    size_t inlen;

    if (!in || !out)
        return -1;

    inlen = strlen(in);
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }
    outbuf = OPENSSL_malloc((inlen / 4) * 3);
    if (!outbuf)
        return -1;

    EVP_DecodeInit(&ctx);
    if (EVP_DecodeUpdate(&ctx, outbuf, &len, (unsigned char *)in, inlen) ==
        -1) {
        OPENSSL_free(outbuf);
        return -1;
    }
    *out = outbuf;
    return len;
}

SCT *SCT_new_from_base64(unsigned char version, const char *logid_base64,
                         log_entry_type_t entry_type, uint64_t timestamp,
                         const char *extensions_base64,
                         const char *signature_base64)
{
    SCT *sct;
    unsigned char *dec = NULL;
    int declen;

    if (!logid_base64 || !extensions_base64 || !signature_base64) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sct = SCT_new();

    if (!sct) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /*
     * RFC6962 section 4.1 says we "MUST NOT expect this to be 0", but we
     * can only construct SCT versions that have been defined.
     */
    if (!SCT_set_version(sct, version)) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, CT_R_SCT_UNSUPPORTED_VERSION);
        goto err;
    }

    dec = NULL;
    declen = sct_base64_decode(logid_base64, &dec);
    if (declen < 0) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
        goto err;
    }

    SCT_set0_log_id(sct, dec, declen);
    dec = NULL;

    declen = sct_base64_decode(extensions_base64, &dec);
    if (declen < 0) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
        goto err;
    }

    SCT_set0_extensions(sct, dec, declen);
    dec = NULL;

    declen = sct_base64_decode(signature_base64, &dec);
    if (declen < 0) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
        goto err;
    }
    /*
     * This explicitly rejects empty signatures: they're invalid for
     * all supported algorithms.
     */
    if (declen <= 4)
        goto err;
    else {
        int siglen;
        unsigned char *p = dec;
        /* Get hash and signature algorithm */
        sct->hash_alg = *p++;
        sct->sig_alg = *p++;
        /* Check they are recognised */
        if (SCT_get_signature_nid(sct) == NID_undef)
            goto err;
        /*
         * Retrieve signature and check it is consistent with the buffer
         * length.
         */
        n2s(p, siglen);
        declen -= 4;
        if (siglen != declen)
            goto err;
        /* modify buffer so have the raw signature at the start */
        memmove(dec, dec + 4, declen);
    }

    SCT_set0_signature(sct, dec, declen);
    dec = NULL;

    SCT_set_timestamp(sct, timestamp);

    if (!SCT_set_log_entry_type(sct, entry_type))
        return sct;

 err:
    OPENSSL_free(dec);
    SCT_free(sct);
    return NULL;
}

#endif
