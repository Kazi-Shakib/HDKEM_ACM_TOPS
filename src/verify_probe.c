/*
 * verify_probe.c — does gandalf_verify reject what it must?
 *
 * Prompted by a client log in which verification of a ZERO-LENGTH message
 * returned success:
 *
 *     [DEBUG] Message to verify length: 0 bytes
 *     [DEBUG] Server ID length: 0
 *     [GANDALF] Verified Valid (norm 5947)
 *     [DEBUG-CLIENT] Server signature verification SUCCESS
 *
 * A signature scheme that accepts an empty message accepts anything an
 * attacker can arrange to parse as empty. Framing bugs upstream then become
 * authentication bypasses rather than connection failures, which is the
 * difference between a broken build and a broken protocol.
 *
 * Every case below is one an honest implementation must reject. The probe
 * fails loudly if any of them is accepted.
 *
 * Build:
 *   gcc -O0 -g -I. -o verify_probe verify_probe.c hdkem_primitives.o \
 *       /usr/local/lib/liboqs.a -lcrypto -ldl -lsodium -lm -lpthread
 */

#include "hdkem_primitives.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int fails = 0;

static void expect_reject(const char *what, int rc)
{
    if (rc == 0) { printf("  FAIL  %-42s accepted (rc=0)\n", what); fails++; }
    else         { printf("  ok    %-42s rejected (rc=%d)\n", what, rc); }
}

static void expect_accept(const char *what, int rc)
{
    if (rc == 0) { printf("  ok    %-42s accepted\n", what); }
    else         { printf("  FAIL  %-42s rejected (rc=%d)\n", what, rc); fails++; }
}

int main(void)
{
    uint8_t pkS[GANDALF_PUBLIC_KEY_SIZE], skS[GANDALF_SECRET_KEY_SIZE];
    uint8_t pkC[GANDALF_PUBLIC_KEY_SIZE], skC[GANDALF_SECRET_KEY_SIZE];
    uint8_t pkX[GANDALF_PUBLIC_KEY_SIZE], skX[GANDALF_SECRET_KEY_SIZE];

    if (gandalf_keypair(pkS, skS) || gandalf_keypair(pkC, skC) ||
        gandalf_keypair(pkX, skX)) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }

    uint8_t ring_keys[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(ring_keys, pkS, GANDALF_PUBLIC_KEY_SIZE);
    memcpy(ring_keys + GANDALF_PUBLIC_KEY_SIZE, pkC, GANDALF_PUBLIC_KEY_SIZE);

    gandalf_ring_t as_client = { .ring_public_keys = ring_keys,
                                 .ring_size = 2, .signer_index = 1 };
    gandalf_ring_t as_server = { .ring_public_keys = ring_keys,
                                 .ring_size = 2, .signer_index = 0 };

    /* A ring containing neither signer. */
    uint8_t other_keys[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(other_keys, pkX, GANDALF_PUBLIC_KEY_SIZE);
    memcpy(other_keys + GANDALF_PUBLIC_KEY_SIZE, pkX, GANDALF_PUBLIC_KEY_SIZE);
    gandalf_ring_t foreign = { .ring_public_keys = other_keys,
                               .ring_size = 2, .signer_index = 1 };

    uint8_t msg[512];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 7 + 1);

    uint8_t sig[GANDALF_SIGNATURE_SIZE];
    if (gandalf_sign(skC, msg, sizeof msg, &as_client, sig) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }

    printf("=== baseline: an honest signature must verify ===\n");
    expect_accept("genuine signature, correct ring",
                  gandalf_verify(msg, sizeof msg, sig, &as_client));

    printf("\n=== the case from the client log ===\n");
    expect_reject("zero-length message",
                  gandalf_verify(msg, 0, sig, &as_client));
    expect_reject("zero-length message, NULL pointer",
                  gandalf_verify(NULL, 0, sig, &as_client));

    printf("\n=== message substitution ===\n");
    {
        uint8_t alt[512];
        memcpy(alt, msg, sizeof alt);
        alt[0] ^= 0x01;
        expect_reject("one bit flipped in the message",
                      gandalf_verify(alt, sizeof alt, sig, &as_client));
    }
    expect_reject("message truncated by one byte",
                  gandalf_verify(msg, sizeof msg - 1, sig, &as_client));
    expect_reject("prefix of the message (32 bytes)",
                  gandalf_verify(msg, 32, sig, &as_client));

    printf("\n=== signature tampering ===\n");
    {
        uint8_t bad[GANDALF_SIGNATURE_SIZE];
        memcpy(bad, sig, sizeof bad);
        bad[0] ^= 0x01;
        expect_reject("first signature byte flipped",
                      gandalf_verify(msg, sizeof msg, bad, &as_client));

        memcpy(bad, sig, sizeof bad);
        bad[GANDALF_SIGNATURE_SIZE / 2] ^= 0x01;
        expect_reject("middle signature byte flipped",
                      gandalf_verify(msg, sizeof msg, bad, &as_client));

        memcpy(bad, sig, sizeof bad);
        bad[GANDALF_SIGNATURE_SIZE - 1] ^= 0x01;
        expect_reject("last signature byte flipped",
                      gandalf_verify(msg, sizeof msg, bad, &as_client));

        memset(bad, 0, sizeof bad);
        expect_reject("all-zero signature",
                      gandalf_verify(msg, sizeof msg, bad, &as_client));
    }

    printf("\n=== ring substitution ===\n");
    expect_reject("ring containing neither signer",
                  gandalf_verify(msg, sizeof msg, sig, &foreign));
    expect_reject("ring_size = 1 (unsupported)",
                  gandalf_verify(msg, sizeof msg, sig,
                                 &(gandalf_ring_t){ .ring_public_keys = ring_keys,
                                                    .ring_size = 1,
                                                    .signer_index = 0 }));
    expect_reject("ring_size = 3 (unsupported)",
                  gandalf_verify(msg, sizeof msg, sig,
                                 &(gandalf_ring_t){ .ring_public_keys = ring_keys,
                                                    .ring_size = 3,
                                                    .signer_index = 0 }));
    expect_reject("NULL ring",
                  gandalf_verify(msg, sizeof msg, sig, NULL));

    /* Whether verification is anonymous in the ring is the point of the
     * scheme: a signature by member 1 must verify against the ring
     * regardless of which index the verifier nominates, or the signature
     * identifies its signer and there is no deniability. Reported rather
     * than asserted, because which convention this implementation uses
     * determines how the endpoints must call it. */
    printf("\n=== signer index convention (informational) ===\n");
    {
        int rc = gandalf_verify(msg, sizeof msg, sig, &as_server);
        printf("  signature by member 1, verified with signer_index=0: rc=%d\n", rc);
        printf("  %s\n", rc == 0
               ? "index-independent: verification does not reveal the signer"
               : "index-dependent: the verifier must know which member signed,\n"
                 "        which is a property worth stating explicitly in the paper");
    }

    printf("\n=== %s ===\n", fails ? "PROBLEMS FOUND" : "all rejections correct");
    return fails ? 1 : 0;
}
