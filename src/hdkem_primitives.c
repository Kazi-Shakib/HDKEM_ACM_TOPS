/* HDKEM cryptographic primitives, artifact v9 (Gandalf + FalconRS runnable).
 *
 * This file contains only the primitives used by the protocol endpoints.
 * The previous in-process BB84 "QKD" generator has been removed: it did not
 * perform error correction and therefore was not a faithful two-party QKD
 * service. The protocol now consumes the explicit (kid3,k3) source interface
 * in hdkem_wire.h; a real QKD deployment supplies that interface externally.
 *
 * Gandalf Figure 5 is implemented directly below.  Its public key is the
 * raw 896-byte NTRU ring element h and its two-member signature is 1236
 * bytes (= 24-byte salt + two 606-byte compressed u_i values).
 *
 * This runnable artifact uses PQClean Falcon-512's NTRU trapdoor/keygen
 * and preimage sampler as a compatibility backend.  The paper's concrete
 * security instantiation uses Antrag TpdGen + MitakaZ PreSmp instead.
 * Therefore the code implements Gandalf's ring-signature algebra and wire
 * format, but is NOT claimed to reproduce the Antrag+MitakaZ backend.
 *
 * FalconRS is the second ring-signature scheme the paper analyzes
 * (897-byte pk, 1288-byte two-member signature). falconrs_keypair() is
 * implemented (Falcon-512 keys; independent of Gandalf); falconrs_sign()/
 * falconrs_verify() implement Algorithm 8 of Hashimoto, Katsumata, Niot,
 * Tucker, Wiggers, "A Comprehensive Study of the Signal Handshake
 * Protocol" (merged NIST PQC Conf. version of ePrint 2025/040 and
 * 2025/1090) — see the citation above falconrs_sign() below.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "hdkem_primitives.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>
#include <oqs/oqs.h>

/* ── Falcon source: include inner.h from the pqclean tree ── */
#define FALCON_RANDOM 1
#include "inner.h"
#include "api.h"

/* Unity build — compile all Falcon C files in one TU */
#include "codec.c"
#include "common.c"
#include "fft.c"
#include "fpr.c"
#include "keygen.c"
#include "rng.c"
#include "sign.c"
#include "vrfy.c"
#include "pqclean.c"

/* ── Shared NTRU/Falcon ring parameters ── */
#define GANDALF_N        512
#define GANDALF_LOGN     9
#define GANDALF_Q        12289

/*
 * Gandalf (Gajland--Janneck--Kiltz, CRYPTO'24 full version):
 *   - kappa = 2 uses tau = 1.2 and beta = 7661;
 *   - verification key size = 896 bytes;
 *   - signature size = 606*k + 24 = 1236 bytes for k = 2;
 *   - concrete instantiation: Antrag TpdGen + MitakaZ PreSmp.
 *
 * IMPORTANT: tau is the GLOBAL NORM tailcut rate in
 * beta = tau*s*sqrt((kappa+1)N).  It is not a per-coefficient cutoff.
 */
#define GANDALF_BETA_SQ       58690921ULL   /* 7661^2 */
#define GANDALF_BETA_F        7661.0
#define GANDALF_SALT_LEN      24u
#define GANDALF_S             162.903513
#define GANDALF_REF_PK_SIZE   896u
#define GANDALF_REF_SIG_SIZE  1236u

/* Falcon-512 encoded sizes used only by FalconRS helpers. */
#define FALCON_ENCODED_PK_SIZE 897u
#define FALCON_ENCODED_SK_SIZE 1281u

/* ============================================================
 * Internal: decode Falcon-512 encoded secret key → (f,g,F,G) (FalconRS only)
 * ============================================================ */
extern const uint8_t PQCLEAN_FALCON512_CLEAN_max_fg_bits[];
extern const uint8_t PQCLEAN_FALCON512_CLEAN_max_FG_bits[];

typedef struct { int8_t f[512], g[512], F[512], G[512]; } _privkey_t;

static int _privkey_decode(const uint8_t *sk, _privkey_t *p)
{
    uint8_t tmp[8 * GANDALF_N];
    size_t u = 1, v;
    if (sk[0] != (uint8_t)(0x50 + GANDALF_LOGN)) return -1;

    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
            p->f, GANDALF_LOGN, PQCLEAN_FALCON512_CLEAN_max_fg_bits[GANDALF_LOGN],
            sk+u, FALCON_ENCODED_SK_SIZE-u);
    if (!v) return -1; u += v;

    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
            p->g, GANDALF_LOGN, PQCLEAN_FALCON512_CLEAN_max_fg_bits[GANDALF_LOGN],
            sk+u, FALCON_ENCODED_SK_SIZE-u);
    if (!v) return -1; u += v;

    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
            p->F, GANDALF_LOGN, PQCLEAN_FALCON512_CLEAN_max_FG_bits[GANDALF_LOGN],
            sk+u, FALCON_ENCODED_SK_SIZE-u);
    if (!v) return -1; u += v;

    if (u != FALCON_ENCODED_SK_SIZE) return -1;
    if (!PQCLEAN_FALCON512_CLEAN_complete_private(
            p->G, p->f, p->g, p->F, GANDALF_LOGN, tmp)) return -1;
    return 0;
}

/* ============================================================
 * Internal: decode Falcon-512 public key → raw uint16_t[N] in [0,q) (FalconRS only)
 * ============================================================ */
static int _pubkey_decode(const uint8_t *pk, uint16_t h[GANDALF_N])
{
    if (pk[0] != (uint8_t)(0x00 + GANDALF_LOGN)) return -1;
    return PQCLEAN_FALCON512_CLEAN_modq_decode(
               h, GANDALF_LOGN, pk+1, FALCON_ENCODED_PK_SIZE - 1) == (FALCON_ENCODED_PK_SIZE - 1) ? 0 : -1;
}

/* ============================================================
 * Internal: H(r, m, ρ) → Rq   (SHAKE256 random oracle)
 * ============================================================ */
static void _gandalf_H(const uint8_t *r,  size_t rlen,
                       const uint8_t *m,  size_t mlen,
                       const uint8_t *pks,size_t pkslen,
                       uint16_t c[GANDALF_N])
{
    static const uint8_t DST[] = "Gandalf-v1-H-CRYPTO2024";
    inner_shake256_context sc;
    uint8_t tmp[2 * GANDALF_N * 2];
    uint8_t lb[2];
#define INJ(buf,len) \
    lb[0]=(uint8_t)((len)>>8);lb[1]=(uint8_t)((len)&0xFF); \
    inner_shake256_inject(&sc,lb,2); \
    inner_shake256_inject(&sc,(buf),(len));
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, DST, sizeof DST - 1);
    INJ(r,rlen); INJ(m,mlen); INJ(pks,pkslen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, c, GANDALF_LOGN, tmp);
    inner_shake256_ctx_release(&sc);
#undef INJ
}

/* ============================================================
 * Gandalf nonsigner Gaussian D_{Z^N,s,0}
 *
 * Figure 5 samples u_i <- D_{Z^N,s,0} for every nonsigning ring member.
 * We implement independent coefficient sampling by rejection from the
 * discrete Gaussian mass exp(-x^2/(2s^2)).
 *
 * The mathematical distribution is infinite.  The implementation cuts
 * the support at +/-1605 (~9.85 standard deviations for s=162.903513);
 * the omitted mass is cryptographically negligible for benchmarking, but
 * this finite-precision implementation must not be described as a formal
 * exact sampler for the paper's proof.
 * ============================================================ */
#define GANDALF_GAUSS_CUTOFF 1605

static void _gandalf_sample_D_ZN_s_0(int16_t u[GANDALF_N])
{
    const double inv_2s2 = 1.0 / (2.0 * GANDALF_S * GANDALF_S);
    const uint32_t range = 2u * (uint32_t)GANDALF_GAUSS_CUTOFF + 1u;
    const uint32_t reject_above = (UINT32_MAX / range) * range;

    for (int i = 0; i < GANDALF_N; ++i) {
        for (;;) {
            uint32_t r;
            do {
                randombytes_buf((uint8_t *)&r, sizeof r);
            } while (r >= reject_above);

            const int32_t x = (int32_t)(r % range) - GANDALF_GAUSS_CUTOFF;

            uint64_t rb;
            randombytes_buf((uint8_t *)&rb, sizeof rb);
            const double u01 =
                (double)(rb >> 11) / 9007199254740992.0; /* [0,1) */
            const double p =
                exp(-((double)x * (double)x) * inv_2s2);

            if (u01 <= p) {
                u[i] = (int16_t)x;
                break;
            }
        }
    }
}

/* Gandalf serializes h as the raw 896-byte mod-q encoding: unlike the
 * FalconRS key, there is no leading Falcon logn/header byte. */
static int _gandalf_pubkey_decode(const uint8_t *pk,
                                  uint16_t h[GANDALF_N])
{
    if (!pk) return -1;
    return PQCLEAN_FALCON512_CLEAN_modq_decode(
               h, GANDALF_LOGN, pk, GANDALF_REF_PK_SIZE)
           == GANDALF_REF_PK_SIZE ? 0 : -1;
}

/* ============================================================
 * Internal: negacyclic poly multiply mod (X^N+1, q)
 * ============================================================ */
static void _poly_mul_rq(const int16_t *u, const uint16_t *h, uint16_t *out)
{
    int64_t acc[GANDALF_N];
    memset(acc, 0, GANDALF_N * sizeof(int64_t));
    for (int i = 0; i < GANDALF_N; i++) {
        if (!u[i]) continue;
        for (int j = 0; j < GANDALF_N; j++) {
            int k = i + j;
            int64_t t = (int64_t)u[i] * (int64_t)h[j];
            if (k < GANDALF_N) acc[k] += t;
            else acc[k-GANDALF_N] -= t;
        }
    }
    for (int i = 0; i < GANDALF_N; i++) {
        int64_t v = acc[i] % GANDALF_Q;
        out[i] = (uint16_t)(v < 0 ? v + GANDALF_Q : v);
    }
}

/* ============================================================
 * Internal: norm check  ‖(u0,u1,v)‖² ≤ β² = 7661²
 * ============================================================ */
static int _norm_ok(const int16_t *u0, const int16_t *u1, const uint16_t *v)
{
    uint64_t sq = 0;
    for (int i = 0; i < GANDALF_N; i++) {
        sq += (uint64_t)((int32_t)u0[i]*(int32_t)u0[i]);
        sq += (uint64_t)((int32_t)u1[i]*(int32_t)u1[i]);
        if (sq > GANDALF_BETA_SQ) return 0;
    }
    for (int i = 0; i < GANDALF_N; i++) {
        int32_t vi = (int32_t)v[i];
        if (vi > GANDALF_Q/2) vi -= GANDALF_Q;
        sq += (uint64_t)(vi*vi);
        if (sq > GANDALF_BETA_SQ) return 0;
    }
    return 1;
}

/* ============================================================
 * GANDALF — Figure-5 implementation (two-member ring)
 *
 * Paper algorithm:
 *   Gen:
 *     (f,g,h) <- TpdGen; sk=(f,g), pk=h
 *   Sgn:
 *     u_other <- D_{Z^N,s,0}
 *     c_other  = u_other * h_other
 *     h        = H(salt,m,rho)
 *     c_j      = h - c_other
 *     (u_j,v) <- PreSmp(B_{f,g},s,c_j)
 *     sigma    = salt || u_0 || u_1
 *   Ver:
 *     v = H(salt,m,rho) - sum_i u_i*h_i
 *     accept iff ||(u_0,u_1,v)||_2 <= beta
 *
 * The published full-security transformation uses a 24-byte salt.
 *
 * Backend note:
 *   The concrete Gandalf paper instantiation selects Antrag TpdGen and
 *   MitakaZ PreSmp.  This artifact has no public Antrag implementation to
 *   link, so it uses PQClean Falcon-512 key generation / sign_dyn as the
 *   NTRU trapdoor and preimage-sampling backend.  This makes -r gandalf
 *   fully runnable and faithful to Figure 5's algebra, but NOT reference-
 *   equivalent to the paper's Antrag+MitakaZ concrete instantiation.
 * ============================================================ */

#define GANDALF_U_SLOT 606u
#define GANDALF_MAX_SIGN_ATTEMPTS 4096

/* ============================================================
 * Gandalf 606-byte Gaussian-vector codec
 *
 * The paper's 606-byte/ring-element figure is inherited from Antrag's
 * Gaussian compression, not Falcon's comp_encode().  Falcon's codec is
 * too large for a sigma ~= 162.9 vector and caused the previous
 * `setup failed` in -r gandalf.
 *
 * This artifact uses a fixed canonical Huffman code optimized for the
 * Gandalf nonsigner Gaussian with s = 162.903513.  Symbols are the
 * integers [-1023,1023].  The omitted Gaussian mass outside this range is
 * negligible; signing restarts if the preimage sampler emits a coefficient
 * outside the codec range or if a particular 512-coefficient vector exceeds
 * the 606-byte budget.
 *
 * This is an artifact codec, not a claim of byte-for-byte compatibility
 * with Antrag's published implementation.
 * ============================================================ */
#define GANDALF_CODEC_ABS_MAX 1023
#define GANDALF_CODEC_NSYM    2047
#define GANDALF_CODEC_MAXBITS 37

static const uint8_t _gandalf_huff_len[GANDALF_CODEC_NSYM] = {
    37,37,37,37,37,37,37,37,37,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,35,35,35,35,
    35,35,35,35,35,35,35,35,35,35,35,35,35,35,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,
    34,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,32,32,32,32,32,32,32,32,32,32,32,32,
    32,32,32,32,32,32,32,32,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,30,30,30,
    30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,29,29,29,29,29,29,29,29,29,29,29,29,29,29,29,
    29,29,29,29,29,29,29,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,27,27,27,27,
    27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,26,26,26,26,26,26,26,26,26,26,26,26,26,
    26,26,26,26,26,26,26,26,26,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,
    25,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,23,23,23,23,23,23,23,
    23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,22,22,22,22,22,22,22,22,22,22,22,22,22,
    22,22,22,22,22,22,22,22,22,22,22,22,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,
    21,21,21,21,21,21,21,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,
    20,20,20,20,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,
    19,19,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,
    18,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,
    17,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
    16,16,16,16,16,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,13,13,13,13,13,13,13,13,13,13,13,13,13,
    13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,
    13,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,
    12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,11,11,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,
    12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,13,13,
    13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,
    13,13,13,13,13,13,13,13,13,13,13,13,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,16,16,16,16,16,16,
    16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,17,17,
    17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,18,18,
    18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,19,19,
    19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,19,20,20,20,20,20,
    20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,21,21,21,21,21,21,21,21,
    21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,21,22,22,22,22,22,22,22,22,22,22,22,22,22,
    22,22,22,22,22,22,22,22,22,22,22,22,22,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,23,
    23,23,23,23,23,23,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,24,25,25,
    25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,25,26,26,26,26,26,26,26,26,26,26,
    26,26,26,26,26,26,26,26,26,26,26,26,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,
    27,27,27,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,29,29,29,29,29,29,29,29,
    29,29,29,29,29,29,29,29,29,29,29,29,29,29,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,
    30,30,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,32,32,32,32,32,32,32,32,32,
    32,32,32,32,32,32,32,32,32,32,32,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,34,34,
    34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,35,35,35,35,35,35,35,35,35,35,35,35,35,35,35,
    35,35,35,35,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,36,37,37,37,37,37,37,37,37,37,
};

typedef struct {
    uint64_t code[GANDALF_CODEC_NSYM];
    uint32_t first_code[GANDALF_CODEC_MAXBITS + 1];
    uint16_t first_index[GANDALF_CODEC_MAXBITS + 1];
    uint16_t count[GANDALF_CODEC_MAXBITS + 1];
    uint16_t symbols[GANDALF_CODEC_NSYM];
    int ready;
} _gandalf_huff_t;

static _gandalf_huff_t _gandalf_huff;

static void _gandalf_huff_init(void)
{
    if (_gandalf_huff.ready) return;

    uint32_t next_code[GANDALF_CODEC_MAXBITS + 1] = {0};
    uint16_t pos = 0;

    for (int s = 0; s < GANDALF_CODEC_NSYM; ++s) {
        uint8_t l = _gandalf_huff_len[s];
        if (l == 0 || l > GANDALF_CODEC_MAXBITS) abort();
        _gandalf_huff.count[l]++;
    }

    uint32_t code = 0;
    for (int l = 1; l <= GANDALF_CODEC_MAXBITS; ++l) {
        code = (code + _gandalf_huff.count[l - 1]) << 1;
        _gandalf_huff.first_code[l] = code;
        next_code[l] = code;
        _gandalf_huff.first_index[l] = pos;
        pos += _gandalf_huff.count[l];
    }

    uint16_t write_pos[GANDALF_CODEC_MAXBITS + 1];
    memcpy(write_pos, _gandalf_huff.first_index, sizeof write_pos);

    for (int s = 0; s < GANDALF_CODEC_NSYM; ++s) {
        const uint8_t l = _gandalf_huff_len[s];
        _gandalf_huff.code[s] = next_code[l]++;
        _gandalf_huff.symbols[write_pos[l]++] = (uint16_t)s;
    }

    _gandalf_huff.ready = 1;
}

static int _gandalf_codec_encode(uint8_t out[GANDALF_U_SLOT],
                                 const int16_t u[GANDALF_N])
{
    _gandalf_huff_init();
    memset(out, 0, GANDALF_U_SLOT);

    size_t bitpos = 0;
    const size_t bitcap = (size_t)GANDALF_U_SLOT * 8u;

    for (int i = 0; i < GANDALF_N; ++i) {
        const int32_t x = u[i];
        if (x < -GANDALF_CODEC_ABS_MAX || x > GANDALF_CODEC_ABS_MAX)
            return -1;

        const unsigned sym = (unsigned)(x + GANDALF_CODEC_ABS_MAX);
        const uint8_t nbits = _gandalf_huff_len[sym];
        const uint64_t code = _gandalf_huff.code[sym];

        if (bitpos + nbits > bitcap)
            return -1;

        for (int b = nbits - 1; b >= 0; --b) {
            const unsigned bit = (unsigned)((code >> b) & 1u);
            out[bitpos >> 3] |= (uint8_t)(bit << (7u - (bitpos & 7u)));
            ++bitpos;
        }
    }

    return 0;
}

static int _gandalf_codec_decode(int16_t u[GANDALF_N],
                                 const uint8_t in[GANDALF_U_SLOT])
{
    _gandalf_huff_init();

    const size_t bitcap = (size_t)GANDALF_U_SLOT * 8u;
    size_t bitpos = 0;

    for (int i = 0; i < GANDALF_N; ++i) {
        uint64_t code = 0;
        int decoded = 0;

        for (int l = 1; l <= GANDALF_CODEC_MAXBITS; ++l) {
            if (bitpos >= bitcap)
                return -1;

            const unsigned bit =
                (unsigned)((in[bitpos >> 3] >> (7u - (bitpos & 7u))) & 1u);
            ++bitpos;
            code = (code << 1) | bit;

            const uint16_t cnt = _gandalf_huff.count[l];
            if (!cnt) continue;

            const uint64_t first = _gandalf_huff.first_code[l];
            if (code >= first && code < first + cnt) {
                const uint16_t idx =
                    (uint16_t)(_gandalf_huff.first_index[l] + (code - first));
                const int32_t sym = _gandalf_huff.symbols[idx];
                u[i] = (int16_t)(sym - GANDALF_CODEC_ABS_MAX);
                decoded = 1;
                break;
            }
        }

        if (!decoded) return -1;
    }

    /* Canonical fixed-width form: all unused trailing bits must be zero. */
    while (bitpos < bitcap) {
        const unsigned bit =
            (unsigned)((in[bitpos >> 3] >> (7u - (bitpos & 7u))) & 1u);
        if (bit) return -1;
        ++bitpos;
    }

    return 0;
}

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(GANDALF_SALT_LEN + 2u * GANDALF_U_SLOT
               == GANDALF_SIGNATURE_SIZE,
               "Gandalf wire layout must be 24 + 606 + 606 = 1236 bytes");
#endif

int gandalf_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    if (sodium_init() < 0) return -1;

    uint8_t falcon_pk[FALCON_ENCODED_PK_SIZE];

    /* Compatibility TpdGen: obtain a valid NTRU Falcon trapdoor and h. */
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
            falcon_pk, secret_key) != 0)
        return -1;

    /* Falcon encodes pk as header || modq(h).  Gandalf's pk is h itself. */
    if (falcon_pk[0] != (uint8_t)(0x00 + GANDALF_LOGN))
        return -1;
    memcpy(public_key, falcon_pk + 1, GANDALF_REF_PK_SIZE);
    sodium_memzero(falcon_pk, sizeof falcon_pk);
    return 0;
}

int gandalf_sign(const uint8_t *secret_key,
                 const uint8_t *message, size_t message_len,
                 const gandalf_ring_t *ring,
                 uint8_t *signature)
{
    if (!secret_key || !message || !ring || !signature) return -1;
    if (ring->ring_size != 2 || ring->signer_index > 1) return -1;

    const size_t j = ring->signer_index;
    const size_t other = 1u - j;

    uint16_t h_j[GANDALF_N], h_other[GANDALF_N];
    if (_gandalf_pubkey_decode(
            ring->ring_public_keys + j * GANDALF_REF_PK_SIZE, h_j) != 0 ||
        _gandalf_pubkey_decode(
            ring->ring_public_keys + other * GANDALF_REF_PK_SIZE,
            h_other) != 0)
        return -1;

    _privkey_t priv;
    if (_privkey_decode(secret_key, &priv) != 0)
        return -1;

    uint8_t *tmp = malloc(72u * GANDALF_N * 8u);
    if (!tmp) return -1;

    unsigned norm_rejects = 0, codec_rejects = 0;
    for (int attempt = 0;
         attempt < GANDALF_MAX_SIGN_ATTEMPTS;
         ++attempt) {

        int16_t u_other[GANDALF_N];
        _gandalf_sample_D_ZN_s_0(u_other);

        uint16_t c_other[GANDALF_N];
        _poly_mul_rq(u_other, h_other, c_other);

        uint8_t salt[GANDALF_SALT_LEN];
        randombytes_buf(salt, sizeof salt);

        uint16_t c_tilde[GANDALF_N];
        _gandalf_H(salt, sizeof salt,
                   message, message_len,
                   ring->ring_public_keys,
                   ring->ring_size * GANDALF_REF_PK_SIZE,
                   c_tilde);

        uint16_t c_j[GANDALF_N];
        for (int i = 0; i < GANDALF_N; ++i) {
            int32_t d = (int32_t)c_tilde[i] - (int32_t)c_other[i];
            if (d < 0) d += GANDALF_Q;
            c_j[i] = (uint16_t)d;
        }

        /* Compatibility PreSmp backend.  sign_dyn samples a short
         * preimage for c_j under the decoded NTRU trapdoor. */
        int16_t u_j[GANDALF_N];
        inner_shake256_context rng_ctx;
        uint8_t seed[48];
        randombytes_buf(seed, sizeof seed);
        inner_shake256_init(&rng_ctx);
        inner_shake256_inject(&rng_ctx, seed, sizeof seed);
        inner_shake256_flip(&rng_ctx);
        PQCLEAN_FALCON512_CLEAN_sign_dyn(
            u_j, &rng_ctx,
            priv.f, priv.g, priv.F, priv.G,
            c_j, GANDALF_LOGN, tmp);
        inner_shake256_ctx_release(&rng_ctx);
        sodium_memzero(seed, sizeof seed);

        /* Reconstruct v exactly as Verify will. */
        uint16_t p_j[GANDALF_N], p_other[GANDALF_N], v[GANDALF_N];
        _poly_mul_rq(u_j, h_j, p_j);
        _poly_mul_rq(u_other, h_other, p_other);

        for (int i = 0; i < GANDALF_N; ++i) {
            int32_t z = (int32_t)c_tilde[i]
                      - (int32_t)p_j[i]
                      - (int32_t)p_other[i];
            z %= GANDALF_Q;
            if (z < 0) z += GANDALF_Q;
            v[i] = (uint16_t)z;
        }

        const int16_t *u0 = (j == 0) ? u_j : u_other;
        const int16_t *u1 = (j == 0) ? u_other : u_j;

        /* A signer must not emit a signature that its verifier rejects. */
        if (!_norm_ok(u0, u1, v)) {
            ++norm_rejects;
            continue;
        }

        uint8_t slot0[GANDALF_U_SLOT];
        uint8_t slot1[GANDALF_U_SLOT];
        memset(slot0, 0, sizeof slot0);
        memset(slot1, 0, sizeof slot1);

        /* The published wire target budgets 606 compressed bytes per u_i.
         * If PQClean's Falcon codec cannot fit this particular sample,
         * restart rather than changing the wire size. */
        if (_gandalf_codec_encode(slot0, u0) != 0 ||
            _gandalf_codec_encode(slot1, u1) != 0) {
            ++codec_rejects;
            continue;
        }

        memcpy(signature, salt, GANDALF_SALT_LEN);
        memcpy(signature + GANDALF_SALT_LEN,
               slot0, sizeof slot0);
        memcpy(signature + GANDALF_SALT_LEN + GANDALF_U_SLOT,
               slot1, sizeof slot1);

        free(tmp);
        sodium_memzero(&priv, sizeof priv);
        return 0;
    }

    free(tmp);
    sodium_memzero(&priv, sizeof priv);
    fprintf(stderr,
            "gandalf_sign: restart budget exhausted "
            "(norm rejects=%u, codec rejects=%u)\n",
            norm_rejects, codec_rejects);
    return -1;
}

int gandalf_verify(const uint8_t *message, size_t message_len,
                   const uint8_t *signature,
                   const gandalf_ring_t *ring)
{
    if (!message || !signature || !ring) return -1;
    if (ring->ring_size != 2) return -1;

    const uint8_t *salt = signature;
    const uint8_t *slot0 = signature + GANDALF_SALT_LEN;
    const uint8_t *slot1 =
        signature + GANDALF_SALT_LEN + GANDALF_U_SLOT;

    int16_t u0[GANDALF_N], u1[GANDALF_N];
    if (_gandalf_codec_decode(u0, slot0) != 0 ||
        _gandalf_codec_decode(u1, slot1) != 0)
        return -1;

    uint16_t h0[GANDALF_N], h1[GANDALF_N];
    if (_gandalf_pubkey_decode(ring->ring_public_keys, h0) != 0 ||
        _gandalf_pubkey_decode(
            ring->ring_public_keys + GANDALF_REF_PK_SIZE, h1) != 0)
        return -1;

    uint16_t c_tilde[GANDALF_N];
    _gandalf_H(salt, GANDALF_SALT_LEN,
               message, message_len,
               ring->ring_public_keys,
               ring->ring_size * GANDALF_REF_PK_SIZE,
               c_tilde);

    uint16_t p0[GANDALF_N], p1[GANDALF_N], v[GANDALF_N];
    _poly_mul_rq(u0, h0, p0);
    _poly_mul_rq(u1, h1, p1);

    for (int i = 0; i < GANDALF_N; ++i) {
        int32_t z = (int32_t)c_tilde[i]
                  - (int32_t)p0[i]
                  - (int32_t)p1[i];
        z %= GANDALF_Q;
        if (z < 0) z += GANDALF_Q;
        v[i] = (uint16_t)z;
    }

    if (!_norm_ok(u0, u1, v))
        return -1;

#ifndef HDKEM_QUIET
    printf("[GANDALF] Verified (Figure-5 equation, beta=7661)\n");
#endif
    return 0;
}

/* ============================================================
 * FALCONRS — keygen: fully implemented.
 *
 * FalconRS is the ring signature Katsumata, Niot, Tucker & Wiggers
 * construct directly from plain NIST-standardized Falcon-512 (not
 * Gajland/Janneck/Kiltz's Gandalf, despite the superficial name overlap —
 * see the note above falconrs_sign() below). Its keygen is exactly
 * Falcon-512 keygen: 897-byte pk, 1281-byte encoded sk, not Gandalf's Antrag key format.
 * ============================================================ */
int falconrs_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    if (!public_key || !secret_key) return -1;
    if (sodium_init() < 0) return -1;

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(public_key, secret_key) != 0)
        return -1;

#if defined(FALCONRS_SECRET_KEY_SIZE)
    if (FALCONRS_SECRET_KEY_SIZE > FALCON_ENCODED_SK_SIZE) {
        memset(secret_key + FALCON_ENCODED_SK_SIZE, 0,
               FALCONRS_SECRET_KEY_SIZE - FALCON_ENCODED_SK_SIZE);
    }
#endif
    return 0;
}

/* ============================================================
 * FALCONRS — sign/verify.
 *
 * Source: Hashimoto, Katsumata, Niot, Tucker, Wiggers, "A Comprehensive
 * Study of the Signal Handshake Protocol: Bundled Authenticated Key
 * Exchange" — the merged, shortened NIST 6th PQC Standardization
 * Conference version of [HKW25] (ePrint 2025/040) and [Kat+25] (ePrint
 * 2025/1090). Section 9.1, Algorithm 8 ("FalconRS.KeyGen/Sign/Verify"),
 * fetched from
 *   https://csrc.nist.gov/csrc/media/events/2025/sixth-pqc-standardization-conference/
 * (the eprint.iacr.org mirror blocks automated fetches).
 *
 * IMPORTANT — read before trusting this for the paper's numbers:
 * Algorithm 8 as published gives the algorithm shape but not literal byte
 * widths. Two constants below are *derived*, not transcribed verbatim:
 *   - FALCONRS_SALT_LEN = 40: the standard NIST Falcon salt length (320
 *     bits per the Falcon spec [Pre+22]), since \S9.1 states FalconRS
 *     "uses the same base parameters as Falcon-512" and Algorithm 8 writes
 *     salt <- {0,1}^kappa without pinning kappa in the text extracted here.
 *   - U_SLOT_FALCONRS (624 bytes/slot): solved backward from Table 2's
 *     reported 2-ring signature size (1288 B) minus the 40-byte salt,
 *     split across the two u_j slots: (1288-40)/2 = 624.
 * FALCONRS_BETA_SQ below IS transcribed from the paper's own formula,
 * beta_sig = 1.1*sigma*sqrt(3n) with Falcon-512's standard sigma
 * (~165.7366171829776, the value that reproduces the Falcon-512 spec's own
 * published normal-signature bound of ~5833.93 via 1.1*sigma*sqrt(2n) --
 * checked below). eta_prime (tailcut bound) = 1633 is stated explicitly in
 * the paper text and independently reproduced by
 * ceil(sqrt(140*ln2)*sigma) = 1633, so that one is solid.
 *
 * The authors also published a reference implementation:
 *   https://doi.org/10.5281/zenodo.15571694
 * Before using -r falconrs results in the paper, diff this function's
 * behavior (signature size, and ideally test vectors) against that
 * reference rather than trusting the derived constants above on faith.
 *
 * Framing this precisely for the paper: what follows is this artifact's
 * own implementation of Algorithm 8 — not the authors' reference
 * implementation, and not verified against it. It uses this codebase's
 * own domain-separated hash serialization (_falconrs_H) for H(salt, RL, M)
 * and its own uniform-proposal rejection sampler for the tailcut discrete
 * Gaussian (_falconrs_sample_tailcut — a direct discrete-mass rejection sampler, not a rounded
 * continuous-Gaussian approximation; see the comment above that function
 * for the correctness argument) — none of these have been checked
 * byte-for-byte against the reference. Consequently, do not describe results measured
 * here as reproducing "the FalconRS implementation" from the paper, and do
 * not state or imply that this code inherits the paper's proven
 * (mu,delta) = (1+2^-27, 2^-57) deniability bound: that bound was proved
 * for the authors' specific construction and parameter choices, and
 * carrying it over to a from-scratch reimplementation with independently
 * derived salt/slot-width constants requires the cross-check above, not
 * an assumption of equivalence. Call this "our implementation of
 * Algorithm 8" until that cross-check has been done.
 *
 * Everything else follows Algorithm 8 directly:
 *   FalconRS.Sign(rsk_i, M, RL={h_j}):
 *     salt <- random; c = H(salt, RL, M)
 *     for j != i: u_j <- D_{Z^n,sigma,0} tailcut to [-eta', eta']
 *     c' = c - sum_{j!=i} h_j * u_j
 *     (u_i, v) = PreSmp(B_i, sigma, -c')      [[ same trapdoor sampler as
 *                                                 Gandalf: PQCLEAN Falcon-512
 *                                                 sign_dyn ]]
 *     if || (u_j)_j , v+c' || > beta_sig: restart
 *     sig = (salt, {u_j}_j)                    [[ v is NOT sent; the
 *                                                 verifier recomputes it ]]
 *   FalconRS.Verify(RL={h_j}, M, sig=(salt,{u_j})):
 *     c = H(salt, RL, M); v = c - sum_j h_j*u_j
 *     accept iff || (u_j)_j, v || <= beta_sig
 * ============================================================ */
#define FALCONRS_SALT_LEN   40u   /* derived — see block comment above */
#define FALCONRS_ETA_PRIME  1633  /* stated in the paper; independently reproduced */
#define FALCONRS_SIGMA      165.7366171829776 /* standard Falcon-512 sigma */
/* beta_sig^2 = (1.1*sigma*sqrt(3*512))^2, precomputed to avoid a runtime
 * sqrt/pow at every sign/verify (mirrors how GANDALF_BETA_SQ is precomputed
 * above). Recomputed independently: 51052090 (== round(7145.0745...^2)). */
#define FALCONRS_BETA_SQ    51052090ULL

#define FALCONRS_U_SLOT (((size_t)FALCONRS_SIGNATURE_SIZE - FALCONRS_SALT_LEN) / 2u) /* 624 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(FALCONRS_SALT_LEN + 2u * (((unsigned)FALCONRS_SIGNATURE_SIZE - FALCONRS_SALT_LEN) / 2u)
               == FALCONRS_SIGNATURE_SIZE,
               "FALCONRS_SALT_LEN + 2*FALCONRS_U_SLOT must exactly equal FALCONRS_SIGNATURE_SIZE "
               "(1288 is even after subtracting 40, so this should always hold, but if the salt "
               "length above is ever changed to something that doesn't divide evenly, wire "
               "accounting silently goes wrong instead of failing loudly)");
#endif

/* H(salt, RL, M) for FalconRS. Deliberately a distinct domain-separation
 * tag from Gandalf's _gandalf_H — these must never collide, since a
 * cross-scheme collision would let a signature under one scheme's hash be
 * reinterpreted under the other. */
static void _falconrs_H(const uint8_t *salt, size_t saltlen,
                        const uint8_t *ring_pks, size_t ring_pks_len,
                        const uint8_t *m, size_t mlen,
                        uint16_t c[GANDALF_N])
{
    static const uint8_t DST[] = "FalconRS-v1-H-NISTPQC2025";
    inner_shake256_context sc;
    uint8_t tmp[2 * GANDALF_N * 2];
    uint8_t lb[2];
#define INJ(buf,len) \
    lb[0]=(uint8_t)((len)>>8);lb[1]=(uint8_t)((len)&0xFF); \
    inner_shake256_inject(&sc,lb,2); \
    inner_shake256_inject(&sc,(buf),(len));
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, DST, sizeof DST - 1);
    /* Algorithm 8 writes H(salt, RL, M): ring first, then message, exactly
     * mirroring the order used for Gandalf's own H(r,m,rho) call except
     * for message/ring ordering — kept faithful to the paper's literal
     * argument order rather than copying Gandalf's. */
    INJ(salt, saltlen); INJ(ring_pks, ring_pks_len); INJ(m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, c, GANDALF_LOGN, tmp);
    inner_shake256_ctx_release(&sc);
#undef INJ
}

/* Discrete Gaussian D_{Z^n,sigma,0} tailcut to [-eta', eta'], used for the
 * *other* ring member's contribution during Sign (Algorithm 8, Line 7).
 *
 * FIX (was): the previous version of this function sampled via Box-Muller
 * (a continuous Gaussian) and rounded to the nearest integer, then
 * rejected outside [-eta',eta']. That is a rounded continuous Gaussian,
 * not the discrete Gaussian D_{Z,sigma,0} the algorithm specifies — the
 * two distributions share first/second moments but differ pointwise, and
 * the paper's delta=2^-57 bound is a statement about the exact discrete
 * distribution, not an approximation of it. Rounding bias would silently
 * invalidate that bound even with the correct tailcut.
 *
 * NOW: exact rejection sampling directly against the discrete Gaussian's
 * own (unnormalized) probability mass. Propose x uniformly from the
 * integers in [-eta',eta'] (bias-free via rejection on the raw random
 * word), accept with probability exp(-x^2/(2*sigma^2)) — since that ratio
 * is exactly rho_sigma(x)/rho_sigma(0) and the proposal is uniform on the
 * tailcut support, the accepted x is distributed exactly as D_{Z,sigma,0}
 * restricted to [-eta',eta']. This is the standard von Neumann rejection
 * sampler for a discrete Gaussian; unlike Falcon's own production sampler
 * (which uses a CDT/bimodal construction for speed and constant-time
 * behavior) this is not constant-time and averages ~8 trials/coefficient
 * at these parameters (sigma*sqrt(2*pi)/(2*eta'+1) acceptance rate) — a
 * few microseconds per signature, negligible next to Falcon PreSmp's cost,
 * but worth noting if this is ever adapted somewhere timing matters. The
 * lack of constant-time behavior matches the artifact's existing
 * disclosed limitation ("the reference sampler is not constant-time"). */
static void _falconrs_sample_tailcut(int16_t u[GANDALF_N])
{
    const double inv_2sigma2 = 1.0 / (2.0 * FALCONRS_SIGMA * FALCONRS_SIGMA);
    const uint32_t range = 2u * (uint32_t)FALCONRS_ETA_PRIME + 1u; /* [-eta',eta'] inclusive */
    /* Reject raw 32-bit draws above this to avoid modulo bias in r % range. */
    const uint32_t reject_above = (UINT32_MAX / range) * range;

    for (int i = 0; i < GANDALF_N; i++) {
        for (;;) {
            uint32_t r;
            do { randombytes_buf((uint8_t *)&r, sizeof r); } while (r >= reject_above);
            int32_t x = (int32_t)(r % range) - FALCONRS_ETA_PRIME;

            uint64_t rb;
            randombytes_buf((uint8_t *)&rb, sizeof rb);
            double accept_u = (double)(rb >> 11) / 9007199254740992.0; /* uniform [0,1) */
            double p = exp(-((double)x * (double)x) * inv_2sigma2);

            if (accept_u <= p) { u[i] = (int16_t)x; break; }
        }
    }
}

int falconrs_sign(const uint8_t *secret_key, const uint8_t *message, size_t message_len,
                  const gandalf_ring_t *ring, uint8_t *signature)
{
    if (!secret_key||!message||!ring||!signature) return -1;
    if (ring->ring_size != 2) return -1;
    if (ring->signer_index > 1) return -1;

    const size_t j     = ring->signer_index;
    const size_t other = 1 - j;
    const uint8_t *pk_other = ring->ring_public_keys + other * FALCON_ENCODED_PK_SIZE;

    uint16_t h_other[GANDALF_N];
    if (_pubkey_decode(pk_other, h_other) != 0) return -1;

    _privkey_t priv;
    if (_privkey_decode(secret_key, &priv) != 0) return -1;

    uint8_t *tmp = malloc(72 * GANDALF_N * 8);
    if (!tmp) return -1;

    /* Algorithm 8, Line 10: restart on a too-large norm. Bounded retry
     * count so a pathological RNG can't spin forever; the expected number
     * of iterations for correctly-tuned parameters is close to 1. */
    for (int attempt = 0; attempt < 4096; attempt++) {
        uint8_t salt[FALCONRS_SALT_LEN];
        randombytes_buf(salt, sizeof salt);

        int16_t u_other[GANDALF_N];
        _falconrs_sample_tailcut(u_other);
        uint16_t c_other[GANDALF_N];
        _poly_mul_rq(u_other, h_other, c_other);

        uint16_t c_tilde[GANDALF_N];
        _falconrs_H(salt, sizeof salt,
                    ring->ring_public_keys, ring->ring_size * FALCON_ENCODED_PK_SIZE,
                    message, message_len, c_tilde);

        uint16_t cj[GANDALF_N];
        for (int i = 0; i < GANDALF_N; i++) {
            int32_t d = (int32_t)c_tilde[i] - (int32_t)c_other[i];
            cj[i] = (uint16_t)(d < 0 ? d + GANDALF_Q : d);
        }

        int16_t u_j[GANDALF_N];
        {
            inner_shake256_context rng_ctx;
            uint8_t seed[48];
            randombytes_buf(seed, sizeof seed);
            inner_shake256_init(&rng_ctx);
            inner_shake256_inject(&rng_ctx, seed, sizeof seed);
            inner_shake256_flip(&rng_ctx);
            PQCLEAN_FALCON512_CLEAN_sign_dyn(
                    u_j, &rng_ctx,
                    priv.f, priv.g, priv.F, priv.G,
                    cj, GANDALF_LOGN, tmp);
            inner_shake256_ctx_release(&rng_ctx);
        }

        /* Recompute v = c_tilde - u_j*h_j - u_other*h_other and check the
         * combined norm against beta_sig (Line 10). This mirrors Gandalf's
         * _norm_ok but against FALCONRS_BETA_SQ, and, unlike Gandalf's
         * sign path, actually gates acceptance here rather than only at
         * verify time. */
        uint16_t h_j[GANDALF_N];
        if (_pubkey_decode(ring->ring_public_keys + j * FALCON_ENCODED_PK_SIZE, h_j) != 0) { free(tmp); return -1; }
        uint16_t p_j[GANDALF_N], p_other[GANDALF_N], v[GANDALF_N];
        _poly_mul_rq(u_j, h_j, p_j);
        _poly_mul_rq(u_other, h_other, p_other);
        int ok = 1;
        uint64_t sq = 0;
        for (int i = 0; i < GANDALF_N; i++) {
            sq += (uint64_t)((int32_t)u_j[i] * (int32_t)u_j[i]);
            sq += (uint64_t)((int32_t)u_other[i] * (int32_t)u_other[i]);
            if (sq > FALCONRS_BETA_SQ) { ok = 0; break; }
        }
        if (ok) {
            for (int i = 0; i < GANDALF_N; i++) {
                int32_t vi = (int32_t)c_tilde[i] - (int32_t)p_j[i] - (int32_t)p_other[i];
                vi %= GANDALF_Q; if (vi < 0) vi += GANDALF_Q;
                v[i] = (uint16_t)vi;
                int32_t vs = (v[i] > GANDALF_Q/2) ? (int32_t)v[i] - GANDALF_Q : (int32_t)v[i];
                sq += (uint64_t)(vs*vs);
                if (sq > FALCONRS_BETA_SQ) { ok = 0; break; }
            }
        }
        if (!ok) continue; /* restart per Algorithm 8, Line 10 */

        /* sig = (salt, {u_j}_j), slot order fixed by signer_index — same
         * convention as Gandalf's slot0/slot1 assignment. */
        memcpy(signature, salt, FALCONRS_SALT_LEN);
        uint8_t *slot0 = signature + FALCONRS_SALT_LEN;
        uint8_t *slot1 = signature + FALCONRS_SALT_LEN + FALCONRS_U_SLOT;
        const int16_t *u_for_slot0 = (j == 0) ? u_j    : u_other;
        const int16_t *u_for_slot1 = (j == 0) ? u_other : u_j;
        memset(slot0, 0, FALCONRS_U_SLOT);
        memset(slot1, 0, FALCONRS_U_SLOT);
        if (!PQCLEAN_FALCON512_CLEAN_comp_encode(slot0, FALCONRS_U_SLOT, u_for_slot0, GANDALF_LOGN)) continue;
        if (!PQCLEAN_FALCON512_CLEAN_comp_encode(slot1, FALCONRS_U_SLOT, u_for_slot1, GANDALF_LOGN)) continue;
        free(tmp);
        return 0;
    }
    free(tmp);
    fprintf(stderr, "falconrs_sign: exceeded restart budget — FALCONRS_U_SLOT (%zu B) is "
                     "likely too tight; see the derivation comment above falconrs_sign().\n",
                     (size_t)FALCONRS_U_SLOT);
    return -1;
}

int falconrs_verify(const uint8_t *message, size_t message_len,
                    const uint8_t *signature, const gandalf_ring_t *ring)
{
    if (!message||!signature||!ring) return -1;
    if (ring->ring_size != 2) return -1;

    const uint8_t *salt  = signature;
    const uint8_t *slot0 = signature + FALCONRS_SALT_LEN;
    const uint8_t *slot1 = signature + FALCONRS_SALT_LEN + FALCONRS_U_SLOT;

    int16_t u0[GANDALF_N], u1[GANDALF_N];
    size_t n0 = PQCLEAN_FALCON512_CLEAN_comp_decode(u0, GANDALF_LOGN, slot0, FALCONRS_U_SLOT);
    if (n0 == 0) return -1;
    size_t n1 = PQCLEAN_FALCON512_CLEAN_comp_decode(u1, GANDALF_LOGN, slot1, FALCONRS_U_SLOT);
    if (n1 == 0) return -1;

    /* Same canonical-padding check as Gandalf's verify — see the comment
     * there for why this matters for strong (not just EUF-CMA) security. */
    uint8_t pad_acc = 0;
    for (size_t i = n0; i < FALCONRS_U_SLOT; i++) pad_acc |= slot0[i];
    for (size_t i = n1; i < FALCONRS_U_SLOT; i++) pad_acc |= slot1[i];
    if (pad_acc != 0) return -1;

    uint16_t c_tilde[GANDALF_N];
    _falconrs_H(salt, FALCONRS_SALT_LEN,
                ring->ring_public_keys, ring->ring_size * FALCON_ENCODED_PK_SIZE,
                message, message_len, c_tilde);

    uint16_t h0[GANDALF_N], h1[GANDALF_N];
    if (_pubkey_decode(ring->ring_public_keys,       h0) != 0) return -1;
    if (_pubkey_decode(ring->ring_public_keys + FALCON_ENCODED_PK_SIZE, h1) != 0) return -1;

    uint16_t p0[GANDALF_N], p1[GANDALF_N], v[GANDALF_N];
    _poly_mul_rq(u0, h0, p0);
    _poly_mul_rq(u1, h1, p1);

    uint64_t sq = 0;
    for (int i = 0; i < GANDALF_N; i++) {
        sq += (uint64_t)((int32_t)u0[i]*(int32_t)u0[i]);
        sq += (uint64_t)((int32_t)u1[i]*(int32_t)u1[i]);
        if (sq > FALCONRS_BETA_SQ) {
#ifndef HDKEM_QUIET
            printf("[FALCONRS] FAILED norm check (u-part)\n");
#endif
            return -1;
        }
    }
    for (int i = 0; i < GANDALF_N; i++) {
        int32_t vi = (int32_t)c_tilde[i] - (int32_t)p0[i] - (int32_t)p1[i];
        vi %= GANDALF_Q; if (vi < 0) vi += GANDALF_Q;
        v[i] = (uint16_t)vi;
        int32_t vs = (v[i] > GANDALF_Q/2) ? (int32_t)v[i] - GANDALF_Q : (int32_t)v[i];
        sq += (uint64_t)(vs*vs);
        if (sq > FALCONRS_BETA_SQ) {
#ifndef HDKEM_QUIET
            printf("[FALCONRS] FAILED norm check\n");
#endif
            return -1;
        }
    }
#ifndef HDKEM_QUIET
    printf("[FALCONRS] Verified (norm OK, beta_sig^2=%llu)\n", (unsigned long long)FALCONRS_BETA_SQ);
#endif
    return 0;
}

/* ============================================================
 * SHA-256 (FIPS 180-4)
 * ============================================================ */
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct { uint32_t state[8]; uint64_t count; uint8_t buffer[64]; } sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define S1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define s0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define s1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx *c, const uint8_t *d) {
    uint32_t W[64],a,b,cc,dd,e,f,g,h,T1,T2;
    for(int i=0;i<16;i++) W[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for(int i=16;i<64;i++) W[i]=s1(W[i-2])+W[i-7]+s0(W[i-15])+W[i-16];
    a=c->state[0];b=c->state[1];cc=c->state[2];dd=c->state[3];
    e=c->state[4];f=c->state[5];g=c->state[6];h=c->state[7];
    for(int i=0;i<64;i++){T1=h+S1(e)+CH(e,f,g)+K256[i]+W[i];T2=S0(a)+MAJ(a,b,cc);h=g;g=f;f=e;e=dd+T1;dd=cc;cc=b;b=a;a=T1+T2;}
    c->state[0]+=a;c->state[1]+=b;c->state[2]+=cc;c->state[3]+=dd;
    c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;
}
static void sha256_init(sha256_ctx *c){
    c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;c->count=0;
}
static void sha256_update(sha256_ctx *c, const uint8_t *d, size_t len){
    size_t i,idx=c->count&0x3F,plen=64-idx; c->count+=len;
    if(len>=plen){memcpy(&c->buffer[idx],d,plen);sha256_transform(c,c->buffer);
        for(i=plen;i+63<len;i+=64)sha256_transform(c,&d[i]);idx=0;}else i=0;
    memcpy(&c->buffer[idx],&d[i],len-i);
}
static void sha256_final(sha256_ctx *c, uint8_t *h){
    uint8_t bits[8],pad[64]={0x80};uint64_t bc=c->count*8;
    for(int i=0;i<8;i++)bits[7-i]=(uint8_t)(bc>>(i*8));
    size_t idx=c->count&0x3F,plen=(idx<56)?(56-idx):(120-idx);
    sha256_update(c,pad,plen);sha256_update(c,bits,8);
    for(int i=0;i<8;i++){h[i*4]=(uint8_t)(c->state[i]>>24);h[i*4+1]=(uint8_t)(c->state[i]>>16);h[i*4+2]=(uint8_t)(c->state[i]>>8);h[i*4+3]=(uint8_t)c->state[i];}
}
static void sha256(const uint8_t *d, size_t l, uint8_t *h){sha256_ctx c;sha256_init(&c);sha256_update(&c,d,l);sha256_final(&c,h);}

/* ============================================================
 * HMAC-SHA256 (RFC 2104)
 * ============================================================ */
int hmac_sha256(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t *out) {
    if (!key||!msg||!out) return -1;
    uint8_t ki[64],ko[64],tk[32],ih[32];
    if (kl>64){sha256(key,kl,tk);key=tk;kl=32;}
    memset(ki,0x36,64);memset(ko,0x5c,64);
    for(size_t i=0;i<kl;i++){ki[i]^=key[i];ko[i]^=key[i];}
    sha256_ctx c;sha256_init(&c);sha256_update(&c,ki,64);sha256_update(&c,msg,ml);sha256_final(&c,ih);
    sha256_init(&c);sha256_update(&c,ko,64);sha256_update(&c,ih,32);sha256_final(&c,out);
    return 0;
}

/* ============================================================
 * HKDF (RFC 5869)
 * ============================================================ */
int hkdf_extract(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il, uint8_t *prk) {
    uint8_t zs[32]={0};
    if (!salt||sl==0){salt=zs;sl=32;}
    return hmac_sha256(salt,sl,ikm,il,prk);
}
int hkdf_expand(const uint8_t *prk, size_t pl, const uint8_t *info, size_t il,
                uint8_t *okm, size_t ol) {
    if (!prk||!okm||ol==0) return -1;
    size_t n=(ol+31)/32; if(n>255) return -1;
    uint8_t t[32],*tp=NULL; size_t tl=0;
    for (size_t i=1;i<=n;i++){
        uint8_t *m=malloc(tl+il+1); if(!m) return -1;
        size_t off=0;
        if(tp){memcpy(m,tp,tl);off=tl;}
        if(info&&il){memcpy(m+off,info,il);}
        m[off+il]=(uint8_t)i;
        if(hmac_sha256(prk,pl,m,off+il+1,t)!=0){free(m);return -1;}
        free(m);
        size_t cp=(i==n)?(ol-(i-1)*32):32;
        memcpy(okm+(i-1)*32,t,cp);
        tp=t;tl=32;
    }
    return 0;
}
int hkdf(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il,
         const uint8_t *info, size_t infl, uint8_t *okm, size_t ol) {
    uint8_t prk[32];
    if (hkdf_extract(salt,sl,ikm,il,prk)!=0) return -1;
    return hkdf_expand(prk,32,info,infl,okm,ol);
}

/* ============================================================
 * X25519  — raw Curve25519 DH via libsodium
 * FIX: use crypto_scalarmult_curve25519_base for keygen
 *      (not crypto_box_keypair which carries NaCl overhead)
 * ============================================================ */
int x25519_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (!public_key||!secret_key) return -1;
    if (sodium_init()<0) return -1;
    /* Generate a random 32-byte scalar, clamp it, derive public key */
    randombytes_buf(secret_key, 32);
    secret_key[0]  &= 248;
    secret_key[31] &= 127;
    secret_key[31] |= 64;
    if (crypto_scalarmult_curve25519_base(public_key, secret_key) != 0) return -1;
    return 0;
}
int x25519_shared_secret(const uint8_t *sk, const uint8_t *pk, uint8_t *ss) {
    if (!sk||!pk||!ss) return -1;
    if (sodium_init()<0) return -1;
    return (crypto_scalarmult_curve25519(ss, sk, pk) == 0) ? 0 : -1;
}

/* ============================================================
 * ML-KEM-768  (liboqs FIPS 203)
 * ============================================================ */
int mlkem768_keypair(uint8_t *pk, uint8_t *sk) {
    if (!pk||!sk) return -1;
    OQS_KEM *k=OQS_KEM_new(OQS_KEM_alg_ml_kem_768); if(!k) return -1;
    OQS_STATUS r=OQS_KEM_keypair(k,pk,sk); OQS_KEM_free(k);
    return (r==OQS_SUCCESS)?0:-1;
}
int mlkem768_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss) {
    if (!pk||!ct||!ss) return -1;
    OQS_KEM *k=OQS_KEM_new(OQS_KEM_alg_ml_kem_768); if(!k) return -1;
    OQS_STATUS r=OQS_KEM_encaps(k,ct,ss,pk); OQS_KEM_free(k);
    return (r==OQS_SUCCESS)?0:-1;
}
int mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss) {
    if (!sk||!ct||!ss) return -1;
    OQS_KEM *k=OQS_KEM_new(OQS_KEM_alg_ml_kem_768); if(!k) return -1;
    OQS_STATUS r=OQS_KEM_decaps(k,ss,ct,sk); OQS_KEM_free(k);
    return (r==OQS_SUCCESS)?0:-1;
}

/* ============================================================
 * Ascon-128a AEAD  — CORRECTED initialisation
 *
 * FIX: The uploaded version did:
 *        s.x[0] = 0x80400c0600000000ULL;   ← set IV constant
 *        memcpy(&s.x[0], key, 8);           ← immediately overwrote IV with key!
 *
 * Correct Ascon-128a initialisation (Dobraunig et al.):
 *   x[0] = 0x80400c0600000000  (IV constant)
 *   x[1] = first  8 bytes of key   (big-endian)
 *   x[2] = second 8 bytes of key
 *   x[3] = first  8 bytes of nonce
 *   x[4] = second 8 bytes of nonce
 * Then apply pa (12-round permutation), then XOR key into x[3],x[4].
 * ============================================================ */
#define ASCON_RATE       16
#define ASCON_PA_ROUNDS  12
#define ASCON_PB_ROUNDS  8

typedef struct { uint64_t x[5]; } ascon_state_t;

static inline uint64_t _load64be(const uint8_t *p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
           ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|(uint64_t)p[7];
}
static inline void _store64be(uint8_t *p, uint64_t v) {
    p[0]=(uint8_t)(v>>56);p[1]=(uint8_t)(v>>48);p[2]=(uint8_t)(v>>40);p[3]=(uint8_t)(v>>32);
    p[4]=(uint8_t)(v>>24);p[5]=(uint8_t)(v>>16);p[6]=(uint8_t)(v>>8);p[7]=(uint8_t)v;
}
static inline uint64_t ROR64(uint64_t x, int n){ return (x>>n)|(x<<(64-n)); }

static void _ascon_perm(ascon_state_t *s, int rounds) {
    static const uint64_t RC[12]={0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b};
    for (int i=12-rounds;i<12;i++){
        s->x[2]^=RC[i];
        s->x[0]^=s->x[4]; s->x[4]^=s->x[3]; s->x[2]^=s->x[1];
        uint64_t t[5];
        t[0]=s->x[0]^((~s->x[1])&s->x[2]);
        t[1]=s->x[1]^((~s->x[2])&s->x[3]);
        t[2]=s->x[2]^((~s->x[3])&s->x[4]);
        t[3]=s->x[3]^((~s->x[4])&s->x[0]);
        t[4]=s->x[4]^((~s->x[0])&s->x[1]);
        t[1]^=t[0];t[0]^=t[4];t[3]^=t[2];t[2]=~t[2];
        s->x[0]=t[0]^ROR64(t[0],19)^ROR64(t[0],28);
        s->x[1]=t[1]^ROR64(t[1],61)^ROR64(t[1],39);
        s->x[2]=t[2]^ROR64(t[2], 1)^ROR64(t[2], 6);
        s->x[3]=t[3]^ROR64(t[3],10)^ROR64(t[3],17);
        s->x[4]=t[4]^ROR64(t[4], 7)^ROR64(t[4],41);
    }
}

static void _ascon_init(ascon_state_t *s, const uint8_t *key, const uint8_t *nonce) {
    uint64_t k0 = _load64be(key);
    uint64_t k1 = _load64be(key+8);
    s->x[0] = 0x80400c0600000000ULL;   /* IV: rate=128, pa=12, pb=8, keylen=128 */
    s->x[1] = k0;
    s->x[2] = k1;
    s->x[3] = _load64be(nonce);
    s->x[4] = _load64be(nonce+8);
    _ascon_perm(s, ASCON_PA_ROUNDS);
    s->x[3] ^= k0;
    s->x[4] ^= k1;
}

static void _ascon_ad(ascon_state_t *s, const uint8_t *ad, size_t adlen) {
    if (!ad || adlen == 0) { s->x[4] ^= 1; return; }
    /* Process full 16-byte blocks */
    while (adlen >= 16) {
        s->x[0] ^= _load64be(ad);
        s->x[1] ^= _load64be(ad+8);
        _ascon_perm(s, ASCON_PB_ROUNDS);
        ad += 16; adlen -= 16;
    }
    /* Partial block + padding */
    uint8_t pad[16] = {0};
    memcpy(pad, ad, adlen);
    pad[adlen] = 0x80;
    s->x[0] ^= _load64be(pad);
    s->x[1] ^= _load64be(pad+8);
    _ascon_perm(s, ASCON_PB_ROUNDS);
    s->x[4] ^= 1;  /* domain separation */
}

static void _ascon_enc(ascon_state_t *s, const uint8_t *pt, uint8_t *ct, size_t len) {
    while (len >= 16) {
        uint64_t p0 = _load64be(pt);
        uint64_t p1 = _load64be(pt+8);
        uint64_t c0 = s->x[0] ^ p0;
        uint64_t c1 = s->x[1] ^ p1;
        _store64be(ct,   c0);
        _store64be(ct+8, c1);
        s->x[0] = c0; s->x[1] = c1;
        _ascon_perm(s, ASCON_PB_ROUNDS);
        pt+=16; ct+=16; len-=16;
    }
    if (len > 0) {
        uint8_t pad[16]={0}; memcpy(pad, pt, len); pad[len]=0x80;
        uint64_t p0=_load64be(pad), p1=_load64be(pad+8);
        uint64_t c0=s->x[0]^p0, c1=s->x[1]^p1;
        uint8_t ctpad[16]; _store64be(ctpad,c0); _store64be(ctpad+8,c1);
        memcpy(ct, ctpad, len);
        s->x[0]=c0; s->x[1]=c1;
    }
}

static void _ascon_dec(ascon_state_t *s, const uint8_t *ct, uint8_t *pt, size_t len) {
    while (len >= 16) {
        uint64_t c0=_load64be(ct), c1=_load64be(ct+8);
        _store64be(pt,   s->x[0]^c0);
        _store64be(pt+8, s->x[1]^c1);
        s->x[0]=c0; s->x[1]=c1;
        _ascon_perm(s, ASCON_PB_ROUNDS);
        ct+=16; pt+=16; len-=16;
    }
    if (len > 0) {
        /* Ascon-128a partial block decryption (spec Algorithm 1):
         *   pt[i] = state[i] ^ ct[i]   for i in [0, len)
         *   new_state[i] = ct[i]        for i in [0, len)
         *   new_state[len] ^= 0x80      (padding bit)
         */
        uint8_t sb[16];
        _store64be(sb,   s->x[0]);
        _store64be(sb+8, s->x[1]);
        for (size_t i = 0; i < len; i++) {
            pt[i] = sb[i] ^ ct[i];
            sb[i] = ct[i];
        }
        sb[len] ^= 0x80;
        s->x[0] = _load64be(sb);
        s->x[1] = _load64be(sb+8);
    }
}

static void _ascon_tag(ascon_state_t *s, const uint8_t *key, uint8_t *tag) {
    uint64_t k0=_load64be(key), k1=_load64be(key+8);
    s->x[1]^=k0; s->x[2]^=k1;
    _ascon_perm(s, ASCON_PA_ROUNDS);
    s->x[3]^=k0; s->x[4]^=k1;
    _store64be(tag,   s->x[3]);
    _store64be(tag+8, s->x[4]);
}

int ascon_encrypt(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *plaintext, size_t ptlen,
                  const uint8_t *ad, size_t adlen,
                  uint8_t *ciphertext, uint8_t *tag) {
    if (!key||!nonce||!plaintext||!ciphertext||!tag) return -1;
    ascon_state_t s;
    _ascon_init(&s, key, nonce);
    _ascon_ad(&s, ad, adlen);
    _ascon_enc(&s, plaintext, ciphertext, ptlen);
    _ascon_tag(&s, key, tag);
    return 0;
}

int ascon_decrypt(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *ciphertext, size_t ctlen,
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *tag, uint8_t *plaintext) {
    if (!key||!nonce||!ciphertext||!tag||!plaintext) return -1;
    ascon_state_t s;
    _ascon_init(&s, key, nonce);
    _ascon_ad(&s, ad, adlen);
    _ascon_dec(&s, ciphertext, plaintext, ctlen);
    uint8_t computed_tag[16];
    _ascon_tag(&s, key, computed_tag);
    if (sodium_memcmp(tag, computed_tag, 16) != 0) {
        memset(plaintext, 0, ctlen);
        return -1;
    }
    return 0;
}

/* Randomness used by protocol and source emulator. */
int random_bytes(uint8_t *buf, size_t len) {
    if (!buf||len==0) return -1;
    if (sodium_init()<0) return -1;
    randombytes_buf(buf,len);
    return 0;
}
