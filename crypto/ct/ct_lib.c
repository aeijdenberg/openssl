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
#include <openssl/ct.h>
#include "../ssl/ssl_locl.h"
#include "ct_locl.h"

SCT *SCT_new(void)
{
    SCT *sct = OPENSSL_malloc(sizeof(SCT));
    if (!sct)
        CTerr(CT_F_SCT_NEW, ERR_R_MALLOC_FAILURE);
    else
        memset(sct, 0, sizeof(SCT));
    sct->entry_type = UNSET_ENTRY;
    sct->version = -1;
    sct->source = CT_SOURCE_UNKNOWN;
    sct->validation_status = CT_STATUS_NONE;
    sct->log = NULL;
    return sct;
}

void sct_free_internal(SCT *sct)
{
    if (sct->logid)
        OPENSSL_free(sct->logid);
    if (sct->ext)
        OPENSSL_free(sct->ext);
    if (sct->sig)
        OPENSSL_free(sct->sig);
    if (sct->sct)
        OPENSSL_free(sct->sct);
}

void SCT_free(SCT *sct)
{
    if (sct) {
        sct_free_internal(sct);
        OPENSSL_free(sct);
    }
}

int SCT_set_version(SCT *sct, unsigned char version)
{
    if (version != 0) {
        CTerr(CT_F_SCT_SET_VERSION, CT_R_UNSUPPORTED_VERSION);
        return 0;
    }
    sct->version = 0;
    return 1;
}

int SCT_set_source(SCT *sct, sct_source_t source)
{
    int rv = 0;
    if (sct == NULL) {
        CTerr(CT_F_SCT_SET_SOURCE, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    sct->source = source;
    switch (source) {
    case CT_TLS_EXTENSION:
    case CT_OCSP_STAPLED_RESPONSE:
        rv = SCT_set_log_entry_type(sct, X509_ENTRY);
        if (rv != 1)
            goto err;
        break;
    case CT_X509V3_EXTENSION:
        rv = SCT_set_log_entry_type(sct, PRECERT_ENTRY);
        if (rv != 1)
            goto err;
        break;
    default: /* if we aren't sure, leave the log entry type alone */
        break;
    }
    rv = 1;
err:
    return rv;
}

int SCT_set_log_entry_type(SCT *sct, log_entry_type_t entry_type)
{
    if (!sct) {
        CTerr(CT_F_SCT_SET_LOG_ENTRY_TYPE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (entry_type != X509_ENTRY && entry_type != PRECERT_ENTRY) {
        CTerr(CT_F_SCT_SET_LOG_ENTRY_TYPE, CT_R_UNSUPPORTED_ENTRY_TYPE);
        return 0;
    }
    sct->entry_type = entry_type;
    return 1;
}

int SCT_set0_logid(SCT *sct, unsigned char *logid, size_t logidlen)
{
    /* Currently only SHA-256 allowed so length must be SCT_V1_HASHLEN */
    if (logidlen != SCT_V1_HASHLEN) {
        CTerr(CT_F_SCT_SET0_LOGID, CT_R_INVALID_LOGID_LENGTH);
        return 0;
    }
    if (sct->logid)
        OPENSSL_free(sct->logid);
    sct->logid = logid;
    sct->logidlen = logidlen;
    return 1;
}

int SCT_set_timestamp(SCT *sct, uint64_t timestamp)
{
    sct->timestamp = timestamp;
    return 1;
}

int SCT_set_signature_nid(SCT *sct, int nid)
{
    if (nid == NID_sha256WithRSAEncryption)
        sct->sig_alg = TLSEXT_signature_rsa;
    else if (nid == NID_ecdsa_with_SHA256)
        sct->sig_alg = TLSEXT_signature_ecdsa;
    else
        return 0;
    sct->hash_alg = TLSEXT_hash_sha256;
    return 1;
}

int SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t extlen)
{
    if (sct->ext)
        OPENSSL_free(sct->ext);
    sct->ext = ext;
    sct->extlen = extlen;
    return 1;
}

int SCT_set0_signature(SCT *sct, unsigned char *sig, size_t siglen)
{
    if (sct->sig)
        OPENSSL_free(sct->sig);
    sct->sig = sig;
    sct->siglen = siglen;
    return 1;
}

int SCT_get_version(const SCT *sct, unsigned char *version)
{
    if (!sct || !version) {
        CTerr(CT_F_SCT_GET_VERSION, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *version = sct->version;
    return 1;
}

int SCT_get_source(SCT *sct, sct_source_t *source)
{
    if (sct == NULL || source == NULL) {
        CTerr(CT_F_SCT_GET_SOURCE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *source = sct->entry_type;
    return 1;
}

int SCT_get_log_entry_type(SCT *sct, log_entry_type_t *entry_type)
{
    if (sct == NULL || entry_type == NULL) {
        CTerr(CT_F_SCT_GET_LOG_ENTRY_TYPE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *entry_type = sct->entry_type;
    return 1;
}

int SCT_get0_logid(const SCT *sct, unsigned char **logid, size_t *logidlen)
{
    if (!sct || !logid || !logidlen) {
        CTerr(CT_F_SCT_GET0_LOGID, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *logid = sct->logid;
    *logidlen = sct->logidlen;
    return 1;
}

int SCT_get_timestamp(const SCT *sct, uint64_t * timestamp)
{
    if (!sct || !timestamp) {
        CTerr(CT_F_SCT_GET_TIMESTAMP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *timestamp = sct->timestamp;
    return 1;
}

int SCT_get_signature_nid(const SCT *sct)
{
    if (!sct) {
        CTerr(CT_F_SCT_GET_SIGNATURE_NID, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }
    if (sct->version != 0) {
        CTerr(CT_F_SCT_GET_SIGNATURE_NID, CT_R_SCT_UNSUPPORTED_VERSION);
        return -1;
    }
    /* RFC6962 only permits two signature algorithms */
    if (sct->hash_alg == TLSEXT_hash_sha256) {
        if (sct->sig_alg == TLSEXT_signature_rsa)
            return NID_sha256WithRSAEncryption;
        if (sct->sig_alg == TLSEXT_signature_ecdsa)
            return NID_ecdsa_with_SHA256;
    }
    return NID_undef;
}

int SCT_get0_extensions(const SCT *sct, unsigned char **ext, size_t *extlen)
{
    if (!sct || !ext || !extlen) {
        CTerr(CT_F_SCT_GET0_EXTENSIONS, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *ext = sct->ext;
    *extlen = sct->extlen;
    return 1;
}

int SCT_get0_signature(const SCT *sct, unsigned char **sig, size_t *siglen)
{
    if (!sct || !sig || !siglen) {
        CTerr(CT_F_SCT_GET0_SIGNATURE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    *sig = sct->sig;
    *siglen = sct->siglen;
    return 1;
}

/* Check SCT is valid */
int sct_check_format(const SCT *sct)
{
    if (sct->version == -1)
        return 0;
    if (sct->version != 0) {
        /* Just need cached encoding */
        if (sct->sct)
            return 1;
        return 0;
    }
    if (!sct->logid || !sct->sig)
        return 0;
    if (SCT_get_signature_nid(sct) <= 0)
        return 0;
    return 1;
}

/*
 * Check key algorithm and parameters, return copy of key if OK
 * or NULL if invalid.
 */

EVP_PKEY *sct_key_dup(EVP_PKEY *pkey)
{
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_bits(pkey) >= SCT_MIN_RSA_BITS) {
            CRYPTO_add(&pkey->references, CRYPTO_LOCK_EVP_PKEY, 1);
            return pkey;
        }
        CTerr(CT_F_SCT_KEY_DUP, CT_R_RSA_KEY_TOO_WEAK);
        return NULL;
    }
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
        EC_KEY *eck = pkey->pkey.ec;
        const EC_GROUP *cv = EC_KEY_get0_group(eck);
        /* Only P-256 permitted */
        if (!cv || EC_GROUP_get_curve_name(cv) != NID_X9_62_prime256v1) {
            CTerr(CT_F_SCT_KEY_DUP, CT_R_ILLEGAL_CURVE);
            return NULL;
        }
        /*
         * If not uncompressed or named curve return a copy with
         * correct parameters.
         */
        if (EC_KEY_get_conv_form(eck) != POINT_CONVERSION_UNCOMPRESSED
            || EC_GROUP_get_asn1_flag(cv) != OPENSSL_EC_NAMED_CURVE) {
            EVP_PKEY *pkdup;
            EC_KEY *ec = EC_KEY_dup(eck);
            if (!ec) {
                CTerr(CT_F_SCT_KEY_DUP, ERR_R_MALLOC_FAILURE);
                return NULL;
            }
            pkdup = EVP_PKEY_new();
            if (!pkdup) {
                CTerr(CT_F_SCT_KEY_DUP, ERR_R_MALLOC_FAILURE);
                EC_KEY_free(ec);
                return NULL;
            }
            EVP_PKEY_assign_EC_KEY(pkdup, ec);
            EC_KEY_set_conv_form(ec, POINT_CONVERSION_UNCOMPRESSED);
            EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
            return pkdup;
        }
        CRYPTO_add(&pkey->references, CRYPTO_LOCK_EVP_PKEY, 1);
        return pkey;
    }
    CTerr(CT_F_SCT_KEY_DUP, CT_R_UNSUPPORTED_ALGORITHM);
    return NULL;
}
