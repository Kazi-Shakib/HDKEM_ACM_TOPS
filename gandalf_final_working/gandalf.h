/*
 * gandalf.h  --  Gandalf ring signature scheme
 *
 * Faithful implementation of the construction from:
 *   Gajland, Janneck, Kiltz, "Ring Signatures for Deniable AKEM:
 *   Gandalf's Fellowship", CRYPTO 2024. Full version April 2026.
 *   https://eprint.iacr.org/2024/890
 *
 * Construction (Fig. 5, Table 2):
 *   - NTRU ring R_q = Z_q[X]/(X^N+1), N=512, q=12289
 *   - One Falcon-512 keypair per ring member: pk = h ∈ R_q (897 bytes)
 *   - Signature for ring size k: σ = (r, u1,...,uk), |σ| = 606·k + 24 bytes
 *     => k=2: 1236 bytes (matches Table 3 exactly)
 *   - Security: UF-CRA under R-ISIS; MC-Ano under NTRU (full key exposure)
 *
 * Deniability (Section 4, Theorem 5):
 *   DR-Den: Either ring member can simulate a transcript indistinguishable
 *           from a real one. Judge given both secret keys cannot attribute.
 *   HR-Den: Honest-receiver deniability via KEM IND-CPA + SyE PRP.
 *
 * Non-repudiation trade-off:
 *   Deniability and non-repudiation are mutually exclusive (Table 1).
 *   This scheme provides deniability NOT non-repudiation. For non-repudiation,
 *   replace the ring signature with a standard (non-ring) Falcon-512 signature.
 *
 * Instantiation note (Section 5):
 *   We use Falcon-padded-512 from liboqs as the base trapdoor primitive,
 *   consistent with the paper's footnote 7: "other instantiations are also
 *   possible, for instance by directly using Falcon's trapdoor generation."
 *   The ring wrapper follows Figure 5 exactly.
 */

#ifndef GANDALF_H
#define GANDALF_H

#include <stdint.h>
#include <stddef.h>

/* ── sizes (Table 2 / Table 3) ─────────────────────────────────── */
#define GANDALF_N           512      /* dimension of R_q             */
#define GANDALF_Q           12289    /* Falcon/NTRU prime modulus     */
#define GANDALF_SALT_BYTES  24       /* ν = 24 bytes (128-bit + 64)  */
#define GANDALF_PK_BYTES    897      /* one Falcon-512 public key     */
#define GANDALF_SK_BYTES    1281     /* one Falcon-512 secret key     */
#define GANDALF_U_BYTES     666      /* bytes per u_i coefficient     */
#define GANDALF_SIG_K2      (666*2 + 24)   /* 1236 B for |ρ|=2       */
#define GANDALF_MAX_RING    2        /* this implementation: |ρ|=2    */

/* ── error codes ───────────────────────────────────────────────── */
#define GANDALF_OK           0
#define GANDALF_ERR_PARAM   -1
#define GANDALF_ERR_SIGN    -2
#define GANDALF_ERR_VERIFY  -3
#define GANDALF_ERR_MEMORY  -4

/* ── ring descriptor ───────────────────────────────────────────── */
typedef struct {
    const uint8_t *pks;    /* concatenated public keys: pks[i*GANDALF_PK_BYTES] */
    size_t ring_size;      /* must be 2 in this build                           */
    size_t signer_index;   /* which member holds the secret key (0 or 1)        */
} gandalf_ring_t;

/* ── key generation ─────────────────────────────────────────────── */
int gandalf_keygen(uint8_t pk[GANDALF_PK_BYTES],
                   uint8_t sk[GANDALF_SK_BYTES]);

/* ── signing (Fig. 5, Sgn) ──────────────────────────────────────── */
/*
 * Produces σ = (r ‖ u_0 ‖ u_1) of GANDALF_SIG_K2 bytes.
 * ring->signer_index identifies which sk is provided.
 *
 * Deniability: either member can sign any message for ring {pk_0, pk_1}.
 * The signature is indistinguishable from one produced by the other member
 * (Theorem 1, MC-Ano under full key exposure).
 */
int gandalf_sign(const uint8_t sk[GANDALF_SK_BYTES],
                 const uint8_t *msg, size_t msg_len,
                 const gandalf_ring_t *ring,
                 uint8_t sig[GANDALF_SIG_K2]);

/* ── verification (Fig. 5, Ver) ─────────────────────────────────── */
/*
 * Returns GANDALF_OK iff the signature is valid for ring ρ and message msg.
 * Does NOT reveal which member signed (anonymity property).
 */
int gandalf_verify(const uint8_t *msg, size_t msg_len,
                   const uint8_t sig[GANDALF_SIG_K2],
                   const gandalf_ring_t *ring);

/* ── simulation (Theorem 5, Sim for DR-Den) ─────────────────────── */
/*
 * Given either secret key (signer_index identifies which), produce a
 * (msg, sig) pair that is computationally indistinguishable from a real
 * signing by the OTHER member.  This is the DR-Den simulator of Fig. 28.
 *
 * Used to establish plausible deniability: any party with sk_j can claim
 * "I produced this transcript myself", since the outputs are identical in
 * distribution.
 */
int gandalf_simulate(const uint8_t sk[GANDALF_SK_BYTES],
                     const uint8_t *msg, size_t msg_len,
                     const gandalf_ring_t *ring,
                     uint8_t sim_sig[GANDALF_SIG_K2]);

/* ── non-repudiation mode (plain Falcon-512, NOT ring) ───────────── */
/*
 * When non-repudiation is required (e.g. regulatory audit logs),
 * deniability must be surrendered.  These functions provide a standard
 * Falcon-512 signature that IS uniquely attributable to the signer.
 *
 * NOTE: using these functions voids all deniability guarantees.
 */
#define FALCON512_SIG_MAX  752   /* max variable-length Falcon-512 sig */
int falcon512_sign_nonrepudiable(const uint8_t sk[GANDALF_SK_BYTES],
                                  const uint8_t *msg, size_t msg_len,
                                  uint8_t sig[FALCON512_SIG_MAX],
                                  size_t *sig_len);
int falcon512_verify_nonrepudiable(const uint8_t pk[GANDALF_PK_BYTES],
                                    const uint8_t *msg, size_t msg_len,
                                    const uint8_t *sig, size_t sig_len);

/* ── benchmark ─────────────────────────────────────────────────── */
void gandalf_benchmark(void);

#endif /* GANDALF_H */
