#ifndef HDKEM_PRIMITIVES_H
#define HDKEM_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h> /* strcmp, used by rs_scheme_from_name() below */

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical byte sizes used by every endpoint and benchmark. */
#define MLKEM_PUBLIC_KEY_SIZE   1184u
#define MLKEM_SECRET_KEY_SIZE   2400u
#define MLKEM_CIPHERTEXT_SIZE   1088u
#define MLKEM_SHARED_SECRET_SIZE 32u

#define X25519_PUBLIC_KEY_SIZE   32u
#define X25519_SECRET_KEY_SIZE   32u
#define X25519_SHARED_SECRET_SIZE 32u

/*
 * Gandalf, CRYPTO'24 full-version instantiation (k = 2):
 *   verification key: 896 bytes
 *   signature:        606*k + 24 = 1236 bytes
 *
 * This artifact implements Figure 5 directly with the existing PQClean
 * Falcon-512 NTRU trapdoor/preimage-sampling machinery.  The public key
 * is serialized as the raw 896-byte ring element h (Falcon's one-byte
 * public-key header is omitted), while the secret trapdoor keeps Falcon's
 * 1281-byte encoding.
 *
 * IMPORTANT: this is a runnable Figure-5 compatibility instantiation.
 * The Gandalf paper's concrete security instantiation instead chooses
 * Antrag TpdGen + MitakaZ PreSmp.  Do not claim bit-for-bit/reference
 * equivalence to that concrete backend unless it is separately integrated.
 */
#define GANDALF_PUBLIC_KEY_SIZE    896u
#define GANDALF_SECRET_KEY_SIZE   1281u
#define GANDALF_SIGNATURE_SIZE    1236u

/* FalconRS: the second two-member ring-signature scheme this artifact
 * supports. FalconRS is NOT from Gajland/Janneck/Kiltz's Gandalf paper
 * (CRYPTO 2024 / ePrint 2024/890) despite the name overlap — it is the
 * construction Katsumata, Niot, Tucker & Wiggers build directly over
 * plain NIST-standardized Falcon-512 (Hashimoto/Katsumata/Niot/Tucker/
 * Wiggers, "A Comprehensive Study of the Signal Handshake Protocol",
 * merged version of ePrint 2025/040 + 2025/1090, Section 9.1, Algorithm
 * 8). Gandalf is a distinct construction instantiated with Antrag
 * trapdoor generation and MitakaZ preimage sampling.
 *
 * FalconRS.Sign samples the non-signing ring member's u_j as a
 * discrete-Gaussian tailcut sample, uses Falcon preimage sampling
 * (PreSmp) for the signer's own u_i, and restarts if the combined norm
 * exceeds beta_sig; FalconRS.Verify recomputes v from ({u_i}, c) and
 * checks ||({u_i}, v)|| against the same bound. falconrs_keypair(),
 * falconrs_sign(), and falconrs_verify() below implement this — see the
 * detailed derivation, citations, and caveats above falconrs_sign() in
 * hdkem_primitives.c before relying on it for published numbers: this is
 * this artifact's own implementation of Algorithm 8, not the paper
 * authors' reference implementation, and has not been cross-checked
 * against it bit-for-bit.
 */
#define FALCONRS_PUBLIC_KEY_SIZE  897u
#define FALCONRS_SECRET_KEY_SIZE  1281u
#define FALCONRS_SIGNATURE_SIZE   1288u

/* Allocation bounds for scheme-generic endpoint/benchmark buffers. */
#define HDKEM_MAX_RS_PUBLIC_KEY_SIZE FALCONRS_PUBLIC_KEY_SIZE
#define HDKEM_MAX_RS_SECRET_KEY_SIZE FALCONRS_SECRET_KEY_SIZE

#define ASCON_KEY_SIZE   16u
#define ASCON_NONCE_SIZE 16u
#define ASCON_TAG_SIZE   16u

/* The artifact is intentionally two-member only.
 * ring_public_keys points to scheme-specific, tightly packed public keys:
 *   Gandalf:  896-byte stride (Antrag/Gandalf verification keys)
 *   FalconRS: 897-byte stride (Falcon-512 encoded public keys)
 * The selected signer/verifier interprets the stride for its own scheme. */
typedef struct {
    const uint8_t *ring_public_keys;
    size_t ring_size;
    size_t signer_index;
} gandalf_ring_t;

int gandalf_keypair(uint8_t *public_key, uint8_t *secret_key);
int gandalf_sign(const uint8_t *secret_key,
                 const uint8_t *message, size_t message_len,
                 const gandalf_ring_t *ring,
                 uint8_t *signature);
int gandalf_verify(const uint8_t *message, size_t message_len,
                   const uint8_t *signature,
                   const gandalf_ring_t *ring);

/* FalconRS uses plain Falcon-512 key generation and this artifact's
 * implementation of Algorithm 8.  It is independent of the Gandalf
 * backend; Gandalf does NOT reuse Falcon-512 key generation. */
int falconrs_keypair(uint8_t *public_key, uint8_t *secret_key);
int falconrs_sign(const uint8_t *secret_key,
                  const uint8_t *message, size_t message_len,
                  const gandalf_ring_t *ring,
                  uint8_t *signature);
int falconrs_verify(const uint8_t *message, size_t message_len,
                    const uint8_t *signature,
                    const gandalf_ring_t *ring);

/* ---------- scheme-selectable ring-signature dispatch ----------
 * Endpoints and the benchmark should go through these rather than calling
 * gandalf_... / falconrs_... directly, so a scheme is chosen once (CLI
 * flag) and every size/length computation stays consistent with it. */
typedef enum {
    RS_SCHEME_GANDALF  = 0,
    RS_SCHEME_FALCONRS = 1
} rs_scheme_t;

static inline const char *rs_scheme_name(rs_scheme_t s)
{
    switch (s) {
    case RS_SCHEME_GANDALF:  return "gandalf";
    case RS_SCHEME_FALCONRS: return "falconrs";
    default: return "invalid";
    }
}

static inline int rs_scheme_from_name(const char *name, rs_scheme_t *out)
{
    if (!name || !out) return -1;
    if (!strcmp(name, "gandalf"))  { *out = RS_SCHEME_GANDALF;  return 0; }
    if (!strcmp(name, "falconrs")) { *out = RS_SCHEME_FALCONRS; return 0; }
    return -1;
}

static inline size_t rs_public_key_size(rs_scheme_t s)
{
    return s == RS_SCHEME_FALCONRS ? FALCONRS_PUBLIC_KEY_SIZE : GANDALF_PUBLIC_KEY_SIZE;
}

static inline size_t rs_secret_key_size(rs_scheme_t s)
{
    return s == RS_SCHEME_FALCONRS ? FALCONRS_SECRET_KEY_SIZE : GANDALF_SECRET_KEY_SIZE;
}

static inline size_t rs_signature_size(rs_scheme_t s)
{
    return s == RS_SCHEME_FALCONRS ? FALCONRS_SIGNATURE_SIZE : GANDALF_SIGNATURE_SIZE;
}

/* HDKEM_MAX_SIGNATURE_SIZE: fixed-size stack/wire buffers throughout the
 * artifact must be sized to the larger of the two schemes' signatures. */
#define HDKEM_MAX_SIGNATURE_SIZE FALCONRS_SIGNATURE_SIZE /* 1288 >= 1236 */

static inline int rs_keypair(rs_scheme_t s, uint8_t *pk, uint8_t *sk)
{
    return s == RS_SCHEME_FALCONRS ? falconrs_keypair(pk, sk) : gandalf_keypair(pk, sk);
}

static inline int rs_sign(rs_scheme_t s, const uint8_t *sk,
                          const uint8_t *m, size_t mlen,
                          const gandalf_ring_t *ring, uint8_t *sig)
{
    return s == RS_SCHEME_FALCONRS
         ? falconrs_sign(sk, m, mlen, ring, sig)
         : gandalf_sign(sk, m, mlen, ring, sig);
}

static inline int rs_verify(rs_scheme_t s, const uint8_t *m, size_t mlen,
                            const uint8_t *sig, const gandalf_ring_t *ring)
{
    return s == RS_SCHEME_FALCONRS
         ? falconrs_verify(m, mlen, sig, ring)
         : gandalf_verify(m, mlen, sig, ring);
}

int mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int mlkem768_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
int mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss);

int x25519_keypair(uint8_t *public_key, uint8_t *secret_key);
int x25519_shared_secret(const uint8_t *sk, const uint8_t *pk, uint8_t *ss);

int hmac_sha256(const uint8_t *key, size_t kl,
                const uint8_t *msg, size_t ml,
                uint8_t *out);
int hkdf_extract(const uint8_t *salt, size_t sl,
                 const uint8_t *ikm, size_t il,
                 uint8_t *prk);
int hkdf_expand(const uint8_t *prk, size_t pl,
                const uint8_t *info, size_t il,
                uint8_t *okm, size_t ol);
int hkdf(const uint8_t *salt, size_t sl,
         const uint8_t *ikm, size_t il,
         const uint8_t *info, size_t infl,
         uint8_t *okm, size_t ol);

int ascon_encrypt(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *plaintext, size_t ptlen,
                  const uint8_t *ad, size_t adlen,
                  uint8_t *ciphertext, uint8_t *tag);
int ascon_decrypt(const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *ciphertext, size_t ctlen,
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *tag, uint8_t *plaintext);

int random_bytes(uint8_t *buf, size_t len);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(GANDALF_PUBLIC_KEY_SIZE == 896u,
               "Gandalf CRYPTO'24 verification key is 896 bytes");
_Static_assert(GANDALF_SIGNATURE_SIZE == 1236u,
               "Gandalf two-member signature is 606*2 + 24 = 1236 bytes");
_Static_assert(GANDALF_SECRET_KEY_SIZE == 1281u,
               "Gandalf compatibility backend uses Falcon-512 1281-byte trapdoor encoding");
_Static_assert(FALCONRS_PUBLIC_KEY_SIZE == 897u,
               "FalconRS uses Falcon-512 encoded 897-byte public keys");
_Static_assert(FALCONRS_SECRET_KEY_SIZE == 1281u,
               "FalconRS uses Falcon-512 encoded 1281-byte secret keys");
_Static_assert(FALCONRS_SIGNATURE_SIZE == 1288u,
               "FalconRS two-member signature is 1288 bytes");
_Static_assert(HDKEM_MAX_SIGNATURE_SIZE >= GANDALF_SIGNATURE_SIZE,
               "maximum signature buffer must fit Gandalf");
_Static_assert(HDKEM_MAX_SIGNATURE_SIZE >= FALCONRS_SIGNATURE_SIZE,
               "maximum signature buffer must fit FalconRS");
_Static_assert(HDKEM_MAX_RS_PUBLIC_KEY_SIZE >= GANDALF_PUBLIC_KEY_SIZE,
               "maximum RS public-key buffer must fit Gandalf");
_Static_assert(HDKEM_MAX_RS_PUBLIC_KEY_SIZE >= FALCONRS_PUBLIC_KEY_SIZE,
               "maximum RS public-key buffer must fit FalconRS");
_Static_assert(MLKEM_PUBLIC_KEY_SIZE == 1184u,
               "ML-KEM-768 public key is 1184 bytes");
_Static_assert(MLKEM_CIPHERTEXT_SIZE == 1088u,
               "ML-KEM-768 ciphertext is 1088 bytes");
#endif

#ifdef __cplusplus
}
#endif

#endif
