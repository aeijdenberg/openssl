/* crypto/include/internal/ct_int.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org)
 * and Adam Eijdenberg (eijdenberg@google.com) for the OpenSSL project 2015.
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
#ifndef HEADER_CT_LOCL_H
# define HEADER_CT_LOCL_H

# ifdef __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_NO_CT

#  include <openssl/safestack.h>
#  include "crypto/include/internal/cryptlib.h"
#  include <openssl/x509v3.h>
#  include <openssl/evp.h>

/* All hashes are currently SHA256 */
#  define SCT_V1_HASHLEN  32
/* Minimum RSA key size, from RFC6962 */
#  define SCT_MIN_RSA_BITS 2048

/*
 * From RFC6962: opaque SerializedSCT<1..2^16-1>; struct { SerializedSCT
 * sct_list <1..2^16-1>; } SignedCertificateTimestampList;
 */

#  define MAX_SCT_SIZE            65535
#  define MAX_SCT_LIST_SIZE       MAX_SCT_SIZE

typedef enum {CT_STATUS_NONE, CT_STATUS_UNKNOWN_LOG, CT_STATUS_VALID,
              CT_STATUS_INVALID, CT_STATUS_UNVERIFIED,
              CT_STATUS_UNKNOWN_VERSION} sct_validation;

typedef enum {CT_TLS_EXTENSION, CT_X509V3_EXTENSION,
              CT_OCSP_STAPLED_RESPONSE, CT_SOURCE_UNKNOWN} sct_source_t;

typedef struct certificate_transparency_log_st CTLOG;

typedef enum {
    UNSET_ENTRY = -1,
    X509_ENTRY = 0,
    PRECERT_ENTRY = 1
} log_entry_type_t;

typedef enum {
    UNSET_VERSION = -1,
    SCT_V1 = 0
} sct_version_t;

typedef struct {
    sct_version_t version;
    /* If version is not SCT_V1 this contains the encoded SCT */
    unsigned char *sct;
    size_t sct_len;
    /*
     * If version is SCT_V1, fields below contain components of the SCT.
     * "log_id", "ext" and "sig" point to buffers allocated with
     * OPENSSL_malloc().
     */
    unsigned char *log_id;
    size_t log_id_len;

    /*
     * Note, we cannot distinguish between an unset timestamp, and one
     * that is set to 0.  However since CT didn't exist in 1970, no real
     * SCT should ever be set as such.
     */
    uint64_t timestamp;
    unsigned char *ext;
    size_t ext_len;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    size_t sig_len;
    /* Log entry type */
    log_entry_type_t entry_type;
    /* Where did this SCT come from? */
    sct_source_t source;
    /* Has this been validated? */
    sct_validation validation_status;
    /* Which log is it? */
    CTLOG *log;
} SCT;

DECLARE_STACK_OF(SCT)

/*
 * Allocate new SCT.
 * Caller is responsible for calling SCT_free when done.
 */
SCT *SCT_new(void);

/*
 * Free SCT and underlying datastructures.
 */
void SCT_free(SCT *sct);

/*
 * Set the version of an SCT.
 * Returns 1 on success, 0 if the version is unrecognized.
 */
int SCT_set_version(SCT *sct, sct_version_t version);

/*
 * Set the log entry type of an SCT.
 * Returns 1 on success.
 */
int SCT_set_log_entry_type(SCT *sct, log_entry_type_t entry_type);

/*
 * Set the log id of an SCT to point directly to the *log_id specified.
 * The SCT takes ownership of the specified pointer.
 * Returns 1 on success.
 */
int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len);

/*
 * Set the timestamp of an SCT.
 */
void SCT_set_timestamp(SCT *sct, uint64_t timestamp);

/*
 * Set the signature type of an SCT
 * Currently NID_sha256WithRSAEncryption or NID_ecdsa_with_SHA256.
 * Returns 1 on success.
 */
int SCT_set_signature_nid(SCT *sct, int nid);

/*
 * Set the extensions of an SCT to point directly to the *ext specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t ext_len);

/*
 * Set the signature of an SCT to point directly to the *sig specified.
 * The SCT takes ownership of the specified pointer.
 */
void SCT_set0_signature(SCT *sct, unsigned char *sig, size_t sig_len);

/*
 * Returns the version of the SCT.
 */
sct_version_t SCT_get_version(const SCT *sct);

/*
 * Returns the log entry type of the SCT.
 */
log_entry_type_t SCT_get_log_entry_type(const SCT *sct);

/*
 * Set *log_id to point to the log id for the SCT. log_id must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_log_id(const SCT *sct, unsigned char **log_id);

/*
 * Returns the timestamp for the SCT.
 */
uint64_t SCT_get_timestamp(const SCT *sct);

/*
 * Return the nid for the signature used by the SCT.
 * Currently NID_sha256WithRSAEncryption or NID_ecdsa_with_SHA256
 * (or NID_undef).
 */
int SCT_get_signature_nid(const SCT *sct);

/*
 * Set *ext to point to the extension data for the SCT. ext must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext);

/*
 * Set *sig to point to the signature for the SCT. sig must not be NULL.
 * The SCT retains ownership of this pointer.
 * Returns length of the data pointed to.
 */
size_t SCT_get0_signature(const SCT *sct, unsigned char **sig);









/* The following is rough */

typedef struct sct_ctx_st SCT_CTX;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;
typedef struct jf_st JSON_FRAGMENT;

DECLARE_STACK_OF(JSON_FRAGMENT)
DECLARE_STACK_OF(CTLOG)



typedef enum {OBJ_ARRAY, OBJ_DICT, DICT_BEG, ARR_BEG, VAL_TRUE, VAL_FALSE,
              VAL_NULL, VAL_NUMBER, VAL_STRING, SEP_NAME, SEP_VAL,
              NAME_VAL} json_token_type;



/*
 * CT_POLICY_NONE - don't even request SCTs.
 * CT_POLICY_REQUEST - request SCTs - setting has side effect of requesting
 *               OCSP response (as SCTs can also be delivered in this manner).
 *               CT_get_peer_scts() will return them. Will fail the connection
 *               if there's an error, but does not require any SCTs be recognized.
 * CT_POLICY_REQUIRE_ONE - same as request, but fail if at least 1 SCT does not validate.
 */
typedef enum {CT_POLICY_NONE, CT_POLICY_REQUEST, CT_POLICY_REQUIRE_ONE} ct_policy;

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



SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len);
int i2o_SCT(const SCT *sct, unsigned char **out);

int SCT_set_source(SCT *sct, sct_source_t source);
int SCT_get_source(SCT *sct, sct_source_t *source);

SCT *SCT_new_from_base64(const unsigned char version,
                         const char *logid_base64,
                         log_entry_type_t entry_type, uint64_t timestamp,
                         const char *extensions_base64,
                         const char *signature_base64);

SCT_CTX *SCT_CTX_new(void);
void SCT_CTX_free(SCT_CTX * sctx);

int SCT_CTX_set1_cert(SCT_CTX * sctx, X509 *cert, X509 *presigner);
int SCT_CTX_set1_issuer(SCT_CTX * sctx, const X509 *issuer);
int SCT_CTX_set1_issuerpubkey(SCT_CTX * sctx, X509_PUBKEY *pubkey);
int SCT_CTX_set1_pubkey(SCT_CTX * sctx, X509_PUBKEY *pubkey);

int SCT_verify(const SCT_CTX * sctx, const SCT *sct);

int SCT_verify_v1(SCT *sct, X509 *cert, X509 *preissuer,
                  X509_PUBKEY *log_pubkey, X509 *issuer_cert);

int SCT_print(SCT *sct, BIO *out, int indent);

void SCT_LIST_free(STACK_OF(SCT) *a);
STACK_OF(SCT) *o2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp,
                            size_t len);
int i2o_SCT_LIST(STACK_OF(SCT) *a, unsigned char **pp);



/*
 * CT_POLICY_EVAL_CTX accessors and evaluation.
 */
CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void);
void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx);
int CT_POLICY_EVAL_CTX_set_policy(CT_POLICY_EVAL_CTX *ctx, ct_policy policy);
int CT_POLICY_EVAL_CTX_set0_log_store(CT_POLICY_EVAL_CTX *ctx, CTLOG_STORE *log_store);

int CT_evaluate_policy(CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts,
                       X509 *cert, EVP_PKEY *issuer_key);

/*
 * Load JSON list of logs such as downloaded from:
 * http://www.certificate-transparency.org/known-logs
 */
CTLOG_STORE *CTLOG_STORE_new(void);
void CTLOG_STORE_free(CTLOG_STORE *store);
int CTLOG_STORE_set_default_paths(SSL_CTX *ctx);
int CTLOG_STORE_load_file(CTLOG_STORE *store, const char *fpath);
int CTLOG_STORE_set_default_ct_verify_paths(CTLOG_STORE *store);
CTLOG *CTLOG_STORE_get0_log_by_id(const CTLOG_STORE *store, const uint8_t *id);


extern const X509V3_EXT_METHOD v3_ct_scts[];


# endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CT_strings(void);

/* Error codes for the CT functions. */

/* Function codes. */
# define CT_F_CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT         105
# define CT_F_CTLOG_STORE_LOAD_FILE                       106
# define CT_F_CTLOG_WRITE_BIO                             107
# define CT_F_CT_BASE64_DECODE                            108
# define CT_F_CT_BASE64_ENCODE                            109
# define CT_F_CT_EVALUATE_POLICY                          110
# define CT_F_CT_JSON_COMPLETE_ARRAY                      111
# define CT_F_CT_JSON_COMPLETE_DICT                       112
# define CT_F_CT_PARSE_JSON                               113
# define CT_F_CT_PARSE_SCT_LIST                           114
# define CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO          115
# define CT_F_CT_VALIDATE_SCT                             116
# define CT_F_D2I_SCT_LIST                                117
# define CT_F_I2D_SCT_LIST                                118
# define CT_F_I2O_SCT                                     119
# define CT_F_I2O_SCT_LIST                                120
# define CT_F_O2I_SCT                                     121
# define CT_F_O2I_SCT_LIST                                122
# define CT_F_SCT_CTX_NEW                                 123
# define CT_F_SCT_KEY_DUP                                 124
# define CT_F_SCT_NEW                                     100
# define CT_F_SCT_NEW_FROM_BASE64                         125
# define CT_F_SCT_SET0_LOG_ID                             101
# define CT_F_SCT_SET_LOG_ENTRY_TYPE                      102
# define CT_F_SCT_SET_SIGNATURE_NID                       103
# define CT_F_SCT_SET_VERSION                             104
# define CT_F_SCT_VERIFY                                  126
# define CT_F_SCT_VERIFY_V1                               127

/* Reason codes. */
# define CT_R_BAD_WRITE                                   104
# define CT_R_CT_JSON_PARSE_ERROR                         105
# define CT_R_CT_JSON_PARSE_MORE_THAN_ONE_OBJECT          106
# define CT_R_CT_JSON_PARSE_UNICODE_NOT_SUPPORTED         107
# define CT_R_ENCODE_ERROR                                108
# define CT_R_ENCODE_FAILURE                              109
# define CT_R_ILLEGAL_CURVE                               110
# define CT_R_INVALID_LOG_ID_LENGTH                       100
# define CT_R_LOG_ERROR                                   111
# define CT_R_NOT_ENOUGH_SCTS                             112
# define CT_R_NULL_INPUT                                  113
# define CT_R_RSA_KEY_TOO_WEAK                            114
# define CT_R_SCT_INVALID                                 115
# define CT_R_SCT_INVALID_SIGNATURE                       116
# define CT_R_SCT_LIST_INVALID                            117
# define CT_R_SCT_LIST_MALLOC_FAILED                      118
# define CT_R_SCT_LOG_ID_MISMATCH                         119
# define CT_R_SCT_NOT_SET                                 120
# define CT_R_SCT_SET_FAIL                                121
# define CT_R_SCT_UNSUPPORTED_VERSION                     122
# define CT_R_UNRECOGNIZED_SIGNATURE_NID                  101
# define CT_R_UNSUPPORTED_ALGORITHM                       123
# define CT_R_UNSUPPORTED_ENTRY_TYPE                      102
# define CT_R_UNSUPPORTED_VERSION                         103

#ifdef  __cplusplus
}
#endif
#endif
