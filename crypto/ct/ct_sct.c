/* crypto/ct/ct_sct.c */
/* Author: Adam Eijdenberg <adam.eijdenberg@gmail.com>.
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
#include <openssl/tls1.h>
#include "internal/cryptlib.h"
#include "crypto/ct/ct_locl.h"


int CT_server_info_encode_sct_list_bio(BIO *out, STACK_OF(SCT) *scts)
{
    int rv = -1;
    int tentative_rv;
    uint8_t t;
    int i;
    int child_size;

    if (scts == NULL) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_NULL_INPUT);
        goto err;
    }

    child_size = CT_tls_encode_sct_list_bio(NULL, scts);
    if (child_size < 0) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_ENCODE_FAILURE);
        goto err;
    }

    tentative_rv = 2 + 2 + child_size;

    if (out == NULL) {
        rv = tentative_rv;
        goto end;
    }

    for (i = 8; i >= 0; i -= 8) {
        t = (TLSEXT_TYPE_signed_certificate_timestamp >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    for (i = 8; i >= 0; i -= 8) {
        t = (child_size >> i) & 0xff;
        if (BIO_write(out, &t, 1) != 1) {
            CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
            goto err;
        }
    }

    if (CT_tls_encode_sct_list_bio(out, scts) != child_size) {
        CTerr(CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO, CT_R_BAD_WRITE);
        goto err;
    }

    rv = tentative_rv;

err:
end:
    return rv;
}


int CT_tls_encode_sct_list_bio(BIO *out, STACK_OF(SCT) *scts)
{
    int rv = -1;
    int tentative_rv;
    unsigned char *data = NULL;

    tentative_rv = i2o_SCT_LIST(scts, &data);
    if (data == NULL || tentative_rv < 0)
        goto err;

    if (out) {
        if (BIO_write(out, data, tentative_rv) != tentative_rv)
            goto err;
    }

    rv = tentative_rv;

err:
    OPENSSL_free(data);
    return rv;
}


/*
 * Parse a list of SCTs (such as encoded in ASN1 string, or supplied in TLS
 * extension. Results can be NULL, if NULL it will be lazily created.
 * Stack will be appended to.
 * Data can be discarded after parsing.
 *
 * Return 1 on success, 0 on failure.
 */
int CT_parse_sct_list(const uint8_t *data, unsigned short size,
                      STACK_OF(SCT) **results, sct_source_t src)
{
    int rv = 0;
    SCT *sct = NULL;
    STACK_OF(SCT) *res = o2i_SCT_LIST(NULL, &data, size);
    if (res == NULL)
        goto err;

    while ((sct = sk_SCT_pop(res)) != NULL) {
        if (SCT_set_source(sct, src) != 1) {
            CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_SET_FAIL);
            goto err;
        }
        if (*results == NULL) {
            *results = sk_SCT_new_null();
            if (*results == NULL) {
                CTerr(CT_F_CT_PARSE_SCT_LIST, CT_R_SCT_LIST_MALLOC_FAILED);
                goto err;
            }
        }
        sk_SCT_push(*results, sct);
        sct = NULL;
    }

    rv = 1;
err:
    SCT_free(sct);
    SCT_LIST_free(res);

    return rv;
}


/*
 * Given an SCT, a cert, and the public key of the issuer, attempt to validate it.
 * Return 1 if valid, 0 otherwise.
 */
int CT_validate_sct(SCT *sct, X509 *cert, EVP_PKEY *pkey, CTLOG_STORE *store)
{
    int rv = 0;
    SCT_CTX *sctx = NULL;
    X509_PUBKEY *pub = NULL, *pub2 = NULL;
    log_entry_type_t log_entry_type;

    switch (sct->version) {
    case 0: /* v1 */
        break; /* so proceed */
    default:
        sct->validation_status = CT_STATUS_UNKNOWN_VERSION;
        goto end;
    }

    if (sct == NULL) {
        CTerr(CT_F_CT_VALIDATE_SCT, CT_R_NULL_INPUT);
        goto err;
    }
    if (cert == NULL) {
        CTerr(CT_F_CT_VALIDATE_SCT, CT_R_NULL_INPUT);
        goto err;
    }

    if (sct->log == NULL) {
        switch (sct->version) {
        case 0: /* v1 */
            sct->log = CTLOG_STORE_get0_log_by_id(store, sct->logid);
            break;
        }
    }

    if (sct->log == NULL) {
        sct->validation_status = CT_STATUS_UNKNOWN_LOG;
        goto end;
    }

    sctx = SCT_CTX_new();
    if (!sctx)
        goto err;

    if (X509_PUBKEY_set(&pub2, sct->log->public_key) != 1)
        goto err;
    if (SCT_CTX_set1_pubkey(sctx, pub2) != 1)
        goto err;

    if (SCT_get_log_entry_type(sct, &log_entry_type) != 1)
        goto err;

    if (log_entry_type == PRECERT_ENTRY) {
        if (pkey == NULL) {
            /*
             * TODO(aeijdenberg): should we throw error or not?
             * pubkey is not set if "-verify" is not called.
             * For now, let's say no, but call the SCT unverified.
             */
            sct->validation_status = CT_STATUS_UNVERIFIED;
            goto end;
        } else {
            if (X509_PUBKEY_set(&pub, pkey) != 1)
                goto err;
            if (SCT_CTX_set1_issuerpubkey(sctx, pub) != 1)
                goto err;
        }
    }

    if (SCT_CTX_set1_cert(sctx, cert, NULL) != 1)
        goto err;

    if (SCT_verify(sctx, sct) == 1)
        sct->validation_status = CT_STATUS_VALID;
    else
        sct->validation_status = CT_STATUS_INVALID;

end:
    rv = 1;
err:
    X509_PUBKEY_free(pub);
    X509_PUBKEY_free(pub2);
    SCT_CTX_free(sctx);

    return rv;
}

EVP_PKEY *CT_get_public_key_that_signed(const X509_STORE_CTX *ctx)
{
    EVP_PKEY *rv = NULL;
    X509 *cert = NULL;
    int i;

    if (ctx == NULL)
        goto err;

    cert = ctx->cert;
    if (cert == NULL)
        goto err;
    rv = X509_get_pubkey(cert);
    if (rv && (X509_verify(cert, rv) == 1))
        goto end;
    else
        ERR_clear_error(); /* big whoop, didn't expect this to pass anyway */

    EVP_PKEY_free(rv);
    rv = NULL;

    if (ctx->chain == NULL)
        goto end;

    for (i = 0; i < sk_X509_num(ctx->chain); i++) {
        rv = X509_get_pubkey(sk_X509_value(ctx->chain, i));
        if (rv && (X509_verify(cert, rv) == 1)) {
            goto end;
        } else
            ERR_clear_error(); /* no biggie, though curious why first doesn't pass */
        EVP_PKEY_free(rv);
        rv = NULL;
    }
end:
err:
    return rv;
}

CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void)
{
    CT_POLICY_EVAL_CTX *rv = OPENSSL_malloc(sizeof(CT_POLICY_EVAL_CTX));
    if (rv) {
        rv->policy = CT_POLICY_NONE;
        rv->log_store = NULL;
    }
    return rv;
}

void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx)
{
    OPENSSL_free(ctx);
}

int CT_POLICY_EVAL_CTX_set_policy(CT_POLICY_EVAL_CTX *ctx, ct_policy policy)
{
    int rv = 0;
    if (ctx == NULL)
        goto err;
    ctx->policy = policy;
    rv = 1;
err:
    return rv;
}

int CT_POLICY_EVAL_CTX_set0_log_store(CT_POLICY_EVAL_CTX *ctx, CTLOG_STORE *log_store)
{
    int rv = 0;
    if (ctx == NULL)
        goto err;
    ctx->log_store = log_store;
    rv = 1;
err:
    return rv;
}

/*
 * Called after ServerHelloDone. If 1 is not returned, connection is failed.
 */
int CT_evaluate_policy(CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts,
                       X509 *cert, EVP_PKEY *issuer_key)
{
    int fail_on_err = 0;
    int rv = 0;
    int parse_scts = 0;
    int min_needed = 0;
    int bad_count = 0;
    int successful_validated_count = 0;

    if ((ctx == NULL) || (cert == NULL)) {
        CTerr(CT_F_CT_EVALUATE_POLICY, CT_R_NULL_INPUT);
        goto err;
    }

    /* Enforce policy */
    switch (ctx->policy) {
    case CT_POLICY_REQUIRE_ONE:
        min_needed = 1;
        /* deliberately no break, should inherit what request gives you */
    case CT_POLICY_REQUEST:
        parse_scts = 1;
        fail_on_err = 1;
    case CT_POLICY_NONE:
         break; /* nothing */
    }
    if (parse_scts) {
        int count_scts = scts ? sk_SCT_num(scts) : 0;
        int i;
        for (i = 0; i < count_scts; i++) {
            SCT *sct = sk_SCT_value(scts, i);
            if (sct && cert) {
                if (CT_validate_sct(sct, cert, issuer_key, ctx->log_store) != 1)
                    goto err;
                switch (sct->validation_status) {
                case CT_STATUS_VALID:
                    /* TODO(aeijdenberg): de-dupe? */
                    successful_validated_count += 1;
                break;
                case CT_STATUS_INVALID:
                    bad_count += 1;
                break;
                default: /* do nothing */
                break;
                }
            }
        }
    }
    if (successful_validated_count < min_needed) {
        CTerr(CT_F_CT_EVALUATE_POLICY, CT_R_NOT_ENOUGH_SCTS);
        goto err;
    }

    rv = bad_count ? 0 : 1;
err:
    return fail_on_err ? rv : 1;
}
