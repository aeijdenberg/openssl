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
#include "crypto/include/internal/ct_int.h"
#include "crypto/include/internal/ct_int.h"
#include "../ssl/ssl_locl.h"

static void sct_sigalg_print(BIO *out, const SCT *sct)
{
    int nid = SCT_get_signature_nid(sct);
    if (nid <= 0)
        BIO_printf(out, "%02X%02X", sct->hash_alg, sct->sig_alg);
    else
        BIO_printf(out, "%s", OBJ_nid2ln(nid));
}

static void timestamp_print(BIO *out, uint64_t timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0,
                             (int)(timestamp / 86400000),
                             (timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    BIO_snprintf(genstr, sizeof(genstr), "%.14s.%03dZ",
                 ASN1_STRING_data(gen), (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

int SCT_print(SCT *sct, BIO *out, int indent)
{
    BIO_printf(out, "%*sSigned Certificate Timestamp:", indent, "");

    switch (sct->source) {
    case CT_TLS_EXTENSION:
        BIO_printf(out, "\n%*sSource    : TLS Extension", indent + 4, "");
        break;
    case CT_X509V3_EXTENSION:
        BIO_printf(out, "\n%*sSource    : X509v3 Extension", indent + 4, "");
        break;
    case CT_OCSP_STAPLED_RESPONSE:
        BIO_printf(out, "\n%*sSource    : OCSP Stapled Response",
                                                            indent + 4, "");
        break;
    case CT_SOURCE_UNKNOWN:
        BIO_printf(out, "\n%*sSource    : Unknown",
                                                            indent + 4, "");
        break;
    }

    BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");

    if (sct->version == 0) {    /* SCT v1 */
        BIO_printf(out, "v1(0)");

        BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
        BIO_hex_string(out, indent + 16, 16, sct->log_id, sct->log_id_len);

        BIO_printf(out, "\n%*sLog Name  : ", indent + 4, "");
        if (sct->log)
            BIO_printf(out, "%.*s", sct->log->name_len, sct->log->name);
        else
            BIO_printf(out, "Unknown");

        BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
        timestamp_print(out, sct->timestamp);
        BIO_printf(out, " (%"PRIu64")", sct->timestamp);

        BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
        if (sct->ext_len == 0)
            BIO_printf(out, "none");
        else
            BIO_hex_string(out, indent + 16, 16, sct->ext, sct->ext_len);

        BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
        sct_sigalg_print(out, sct);
        BIO_printf(out, "\n%*s            ", indent + 4, "");
        BIO_hex_string(out, indent + 16, 16, sct->sig, sct->sig_len);
    } else {                    /* Unknown version */

        BIO_printf(out, "unknown\n%*s", indent + 16, "");
        BIO_hex_string(out, indent + 16, 16, sct->sct, sct->sct_len);
    }

    BIO_printf(out, "\n%*sStatus    : ", indent + 4, "");
    switch (sct->validation_status) {
    case CT_STATUS_NONE:
        BIO_printf(out, "Unattempted");
        break;
    case CT_STATUS_UNKNOWN_VERSION:
        BIO_printf(out, "Unrecognized SCT version - unable to validate");
        break;
    case CT_STATUS_UNKNOWN_LOG:
        BIO_printf(out, "Unrecognized log - unable to validate");
        break;
    case CT_STATUS_UNVERIFIED:
        BIO_printf(out, "Cert chain not verified - unable to validate");
        break;
    case CT_STATUS_VALID:
        BIO_printf(out, "Valid - success!");
        break;
    case CT_STATUS_INVALID:
        BIO_printf(out, "Invalid - failure!");
        break;
    }
    BIO_printf(out, "\n");

    return 1;
}
