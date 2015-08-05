/* ct.h */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org)
 * and Adam Eijdenberg (eijdenberg@google.com)
 * for the OpenSSL project 2015.
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
#ifndef HEADER_CT_H
# define HEADER_CT_H

# include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sct_st SCT;
typedef struct sct_ctx_st SCT_CTX;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct certificate_transparency_log_st CTLOG;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

typedef enum {
    UNSET_ENTRY = -1,
    X509_ENTRY = 0,
    PRECERT_ENTRY = 1
} log_entry_type_t;

typedef enum {CT_TLS_EXTENSION, CT_X509V3_EXTENSION,
              CT_OCSP_STAPLED_RESPONSE, CT_SOURCE_UNKNOWN} sct_source_t;
/*
 * CT_POLICY_NONE - don't even request SCTs.
 * CT_POLICY_REQUEST - request SCTs - setting has side effect of requesting
 *               OCSP response (as SCTs can also be delivered in this manner).
 *               CT_get_peer_scts() will return them. Will fail the connection
 *               if there's an error, but does not require any SCTs be recognized.
 * CT_POLICY_REQUIRE_ONE - same as request, but fail if at least 1 SCT does not validate.
 */
typedef enum {CT_POLICY_NONE, CT_POLICY_REQUEST, CT_POLICY_REQUIRE_ONE} ct_policy;

SCT *SCT_new(void);
void SCT_free(SCT *sct);
SCT *o2i_SCT(SCT **psct, const unsigned char **in, size_t len);
int i2o_SCT(const SCT *sct, unsigned char **out);

int SCT_set_version(SCT *sct, unsigned char version);
int SCT_set_log_entry_type(SCT *sct, log_entry_type_t entry_type);
int SCT_set_source(SCT *sct, sct_source_t source);
int SCT_set0_logid(SCT *sct, unsigned char *logid, size_t logidlen);
int SCT_set_timestamp(SCT *sct, uint64_t timestamp);
int SCT_set_signature_nid(SCT *sct, int nid);
int SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t extlen);
int SCT_set0_signature(SCT *sct, unsigned char *sig, size_t siglen);

int SCT_get_version(const SCT *sct, unsigned char *version);
int SCT_get_log_entry_type(SCT *sct, log_entry_type_t *entry_type);
int SCT_get_source(SCT *sct, sct_source_t *source);
int SCT_get0_logid(const SCT *sct, unsigned char **logid, size_t *logidlen);
int SCT_get_timestamp(const SCT *sct, uint64_t * timestamp);
int SCT_get_signature_nid(const SCT *sct);
int SCT_get0_extensions(const SCT *sct, unsigned char **ext, size_t *extlen);
int SCT_get0_signature(const SCT *sct, unsigned char **sig, size_t *siglen);

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

DECLARE_STACK_OF(SCT)

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

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CT_strings(void);

/* Error codes for the CT functions. */

/* Function codes. */
# define CT_F_CTLOG_CREATE_LOG_FROM_JSON_FRAGMENT         127
# define CT_F_CTLOG_STORE_LOAD_FILE                       128
# define CT_F_CTLOG_WRITE_BIO                             129
# define CT_F_CT_BASE64_DECODE                            122
# define CT_F_CT_BASE64_ENCODE                            123
# define CT_F_CT_EVALUATE_POLICY                          135
# define CT_F_CT_JSON_COMPLETE_ARRAY                      124
# define CT_F_CT_JSON_COMPLETE_DICT                       125
# define CT_F_CT_PARSE_JSON                               126
# define CT_F_CT_PARSE_SCT_LIST                           132
# define CT_F_CT_SERVER_INFO_ENCODE_SCT_LIST_BIO          133
# define CT_F_CT_VALIDATE_SCT                             134
# define CT_F_D2I_SCT_LIST                                100
# define CT_F_I2D_SCT_LIST                                101
# define CT_F_I2O_SCT                                     102
# define CT_F_I2O_SCT_LIST                                103
# define CT_F_O2I_SCT                                     104
# define CT_F_O2I_SCT_LIST                                105
# define CT_F_SCT_CTX_NEW                                 106
# define CT_F_SCT_GET0_EXTENSIONS                         107
# define CT_F_SCT_GET0_LOGID                              108
# define CT_F_SCT_GET0_SIGNATURE                          109
# define CT_F_SCT_GET_LOG_ENTRY_TYPE                      110
# define CT_F_SCT_GET_SIGNATURE_NID                       111
# define CT_F_SCT_GET_SOURCE                              130
# define CT_F_SCT_GET_TIMESTAMP                           112
# define CT_F_SCT_GET_VERSION                             113
# define CT_F_SCT_KEY_DUP                                 121
# define CT_F_SCT_NEW                                     114
# define CT_F_SCT_NEW_FROM_BASE64                         115
# define CT_F_SCT_SET0_LOGID                              116
# define CT_F_SCT_SET_LOG_ENTRY_TYPE                      117
# define CT_F_SCT_SET_SOURCE                              131
# define CT_F_SCT_SET_VERSION                             118
# define CT_F_SCT_VERIFY                                  119
# define CT_F_SCT_VERIFY_V1                               120
# define CT_F_SSL_APPLY_CERTIFICATE_TRANSPARENCY_POLICY   136
# define CT_F_SSL_CTX_APPLY_CERTIFICATE_TRANSPARENCY_POLICY 137
# define CT_F_SSL_GET_PEER_SCTS                           138
# define CT_F_SSL_VALIDATE_CT                             139

/* Reason codes. */
# define CT_R_BAD_WRITE                                   118
# define CT_R_CT_JSON_PARSE_ERROR                         112
# define CT_R_CT_JSON_PARSE_MORE_THAN_ONE_OBJECT          113
# define CT_R_CT_JSON_PARSE_UNICODE_NOT_SUPPORTED         114
# define CT_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED        123
# define CT_R_ENCODE_ERROR                                115
# define CT_R_ENCODE_FAILURE                              119
# define CT_R_ILLEGAL_CURVE                               109
# define CT_R_INVALID_LOGID_LENGTH                        100
# define CT_R_LOG_ERROR                                   116
# define CT_R_MALLOC_FAILED                               124
# define CT_R_NOT_ENOUGH_SCTS                             122
# define CT_R_NULL_INPUT                                  117
# define CT_R_RSA_KEY_TOO_WEAK                            110
# define CT_R_SCT_INVALID                                 101
# define CT_R_SCT_INVALID_SIGNATURE                       102
# define CT_R_SCT_LIST_INVALID                            103
# define CT_R_SCT_LIST_MALLOC_FAILED                      120
# define CT_R_SCT_LOG_ID_MISMATCH                         104
# define CT_R_SCT_NOT_SET                                 105
# define CT_R_SCT_SET_FAIL                                121
# define CT_R_SCT_UNSUPPORTED_VERSION                     106
# define CT_R_SET_FAILED                                  125
# define CT_R_UNSUPPORTED_ALGORITHM                       111
# define CT_R_UNSUPPORTED_ENTRY_TYPE                      107
# define CT_R_UNSUPPORTED_VERSION                         108

#ifdef  __cplusplus
}
#endif
#endif
