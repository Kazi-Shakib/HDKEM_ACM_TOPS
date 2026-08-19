#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/*
 * Compatibility implementation for the OQS incremental SHAKE256 interface
 * used by the imported Falcon/PQClean sources.
 *
 * We intentionally implement this locally rather than depend on liboqs
 * exporting its internal SHA3 symbols.
 */

typedef struct {
    void *ctx;
} OQS_SHA3_shake256_inc_ctx;

void OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state)
{
    if (!state) return;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        state->ctx = NULL;
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        state->ctx = NULL;
        return;
    }

    state->ctx = ctx;
}

void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state,
                                  const uint8_t *input,
                                  size_t inlen)
{
    if (!state || !state->ctx || (!input && inlen))
        return;

    if (inlen != 0)
        (void)EVP_DigestUpdate((EVP_MD_CTX *)state->ctx, input, inlen);
}

void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state)
{
    /*
     * OpenSSL's SHAKE EVP interface needs no separate transition here.
     * EVP_DigestFinalXOF / EVP_DigestSqueeze performs the XOF transition.
     */
    (void)state;
}

void OQS_SHA3_shake256_inc_squeeze(uint8_t *output,
                                   size_t outlen,
                                   OQS_SHA3_shake256_inc_ctx *state)
{
    if (!state || !state->ctx || (!output && outlen))
        return;

#if OPENSSL_VERSION_NUMBER >= 0x30300000L
    /*
     * OpenSSL >= 3.3 supports repeated XOF squeezing while preserving state.
     */
    (void)EVP_DigestSqueeze((EVP_MD_CTX *)state->ctx, output, outlen);
#else
    /*
     * Older OpenSSL supports a single FinalXOF operation.
     *
     * Your Falcon implementation may invoke squeeze multiple times. If your
     * OpenSSL is older than 3.3, use the alternative discussed below rather
     * than relying on repeated FinalXOF calls.
     */
    (void)EVP_DigestFinalXOF((EVP_MD_CTX *)state->ctx, output, outlen);
#endif
}

void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state)
{
    if (!state)
        return;

    if (state->ctx)
        EVP_MD_CTX_free((EVP_MD_CTX *)state->ctx);

    state->ctx = NULL;
}
