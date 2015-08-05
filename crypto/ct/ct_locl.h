/* crypto/ct/ct_locl.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org)
 * and Adam Eijdenberg (eijdenberg@google.com)
 * for the OpenSSL project 2015.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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
 */


#ifndef HEADER_SCT_INTERNAL_H
# define HEADER_SCT_INTERNAL_H

# include <openssl/ossl_typ.h>
# include <openssl/ct.h>
# include <openssl/safestack.h>

#ifdef    __cplusplus
extern "C" {
#endif


/* All hashes are currently SHA256 */
# define SCT_V1_HASHLEN  32
/* Minimum RSA key size, from RFC6962 */
# define SCT_MIN_RSA_BITS 2048

/*
 * From RFC6962: opaque SerializedSCT<1..2^16-1>; struct { SerializedSCT
 * sct_list <1..2^16-1>; } SignedCertificateTimestampList;
 */

# define MAX_SCT_SIZE            65535
# define MAX_SCT_LIST_SIZE      MAX_SCT_SIZE

typedef struct jf_st JSON_FRAGMENT;

DECLARE_STACK_OF(JSON_FRAGMENT)
DECLARE_STACK_OF(CTLOG)

typedef enum {CT_STATUS_NONE, CT_STATUS_UNKNOWN_LOG, CT_STATUS_VALID,
              CT_STATUS_INVALID, CT_STATUS_UNVERIFIED,
              CT_STATUS_UNKNOWN_VERSION} sct_validation;

typedef enum {OBJ_ARRAY, OBJ_DICT, DICT_BEG, ARR_BEG, VAL_TRUE, VAL_FALSE,
              VAL_NULL, VAL_NUMBER, VAL_STRING, SEP_NAME, SEP_VAL,
              NAME_VAL} json_token_type;

struct sct_st {
    int version;
    /* If version is not 0 this contains the encoded SCT */
    unsigned char *sct;
    size_t sctlen;
    /*
     * If version is 0 fields below contain components of the SCT. "logid",
     * "ext" and "sig" point to buffers allocated with OPENSSL_malloc().
     */
    unsigned char *logid;
    size_t logidlen;
    uint64_t timestamp;
    unsigned char *ext;
    size_t extlen;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    size_t siglen;
    /* Log entry type */
    log_entry_type_t entry_type;
    /* Where did this SCT come from? */
    sct_source_t source;
    /* Has this been validated? */
    sct_validation validation_status;
    /* Which log is it? */
    CTLOG *log;
};

/* The following parameters are used during SCT verification */
struct sct_ctx_st {
    EVP_PKEY *pkey;
    /* Hash of public key */
    unsigned char *pkeyhash;
    size_t pkeyhashlen;
    /* For precertificate, issuer public key hash */
    unsigned char *ihash;
    size_t ihashlen;
    /* certificate encoding */
    unsigned char *certder;
    size_t certderlen;
    /* precertificate encoding */
    unsigned char *preder;
    size_t prederlen;
};

struct jf_st {
    json_token_type type;
    BUF_MEM *buffer;
    struct jf_st *name;
    struct jf_st *value;
    STACK_OF(JSON_FRAGMENT) *children;
};

struct ct_policy_eval_ctx_st {
    ct_policy policy;
    CTLOG_STORE *log_store;
};

struct certificate_transparency_log_st {
    uint8_t                 log_id[SCT_V1_HASHLEN];
    EVP_PKEY                *public_key;
    unsigned char           *name;
    uint16_t                name_len;
};

struct ctlog_store_st {
    STACK_OF(CTLOG) *logs;
};


int sct_check_format(const SCT *sct);
void sct_free_internal(SCT *sct);
EVP_PKEY *sct_key_dup(EVP_PKEY *pkey);

/* JSON stuff */
int CT_json_write_string(BIO *out, const char *data, int len);
BUF_MEM *CT_base64_encode(BUF_MEM *in);
void JSON_FRAGMENT_free(JSON_FRAGMENT *f);
JSON_FRAGMENT *CT_parse_json(const char *data, uint32_t len);
void CT_base64_decode(char *in, uint16_t in_len,
                      char **out, uint16_t *out_len);
const JSON_FRAGMENT *CT_json_get_value(const JSON_FRAGMENT *par,
                                       const char *key);
JSON_FRAGMENT *JSON_FRAGMENT_alloc(json_token_type t);
int CT_json_complete_array(STACK_OF(JSON_FRAGMENT) *frags);
int CT_json_complete_dict(STACK_OF(JSON_FRAGMENT) *frags);

/* Create / free a CT log */
CTLOG *CTLOG_new(const char *pk, uint16_t pkey_len, const char *name,
                 uint16_t name_len);
void CTLOG_free(CTLOG *log);
CTLOG *CTLOG_create_log_from_json_fragment(const JSON_FRAGMENT *log);

/* Log store management */
CTLOG_STORE *CTLOG_STORE_new(void);
void CTLOG_STORE_free(CTLOG_STORE *store);
int CTLOG_write_bio(BIO *out, const CTLOG *log);

/* SCT management */
int CT_server_info_encode_sct_list_bio(BIO *out, STACK_OF(SCT) *scts);
int CT_tls_encode_sct_list_bio(BIO *out, STACK_OF(SCT) *scts);
EVP_PKEY *CT_get_public_key_that_signed(const X509_STORE_CTX *ctx);
int CT_parse_sct_list(const uint8_t *data, unsigned short size,
                      STACK_OF(SCT) **results, sct_source_t src);
int CT_validate_sct(SCT *sct, X509 *cert, EVP_PKEY *pkey, CTLOG_STORE *store);

#ifdef  __cplusplus
}
#endif
#endif
