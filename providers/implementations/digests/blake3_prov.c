/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "blake3.h"

typedef struct {
    blake3_hasher ctx;
} BLAKE3_CTX;

static int ossl_blake3_init(BLAKE3_CTX *ctx)
{
    blake3_hasher_init(&ctx->ctx);
    return 1;
}

static int ossl_blake3_update(BLAKE3_CTX *ctx, const unsigned char *in,
                              size_t inl)
{
    blake3_hasher_update(&ctx->ctx, in, inl);
    return 1;
}

static int ossl_blake3_final(unsigned char *out, BLAKE3_CTX *ctx)
{
    blake3_hasher_finalize(&ctx->ctx, out, BLAKE3_OUT_LEN);
    return 1;
}

/* ossl_blake3_functions */
IMPLEMENT_digest_functions(blake3, BLAKE3_CTX,
    BLAKE3_BLOCK_LEN, BLAKE3_OUT_LEN, PROV_DIGEST_FLAG_ALGID_ABSENT,
    ossl_blake3_init, ossl_blake3_update, ossl_blake3_final)
