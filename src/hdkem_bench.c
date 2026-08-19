/*
 * hdkem_bench.c — regenerates the measured quantities behind Tables 4-7, 9, 10.
 *
 * Differences from the previous in-band timing in hdkem_client.c /
 * hdkem_server.c, in order of how much they change the reported numbers:
 *
 *  1. gandalf_verify is timed against a signature that actually verifies.
 *     The old server driver timed
 *         gandalf_verify(buf, 4, buf, &{.ring_size = 1})
 *     annotated "intentional dummy - will fail but is fast". A rejected
 *     Falcon signature short-circuits before the norm check, so that measures
 *     the reject path, not verification.
 *
 *  2. mlkem768_decapsulate is timed on a real ciphertext, not on the raw
 *     wire buffer at offset 0. FO re-encryption runs either way, so the old
 *     figure was accidentally close, but it was not the protocol path.
 *
 *  3. x25519_shared_secret is timed against an X25519 peer point. The old
 *     server driver passed client_gpk - a Falcon-512 ring public key - as the
 *     peer point, using its first 32 bytes as a curve point.
 *
 *  4. HKDF is timed over the actual IKM, (k1^k2^k3) || sig || c || IDc || IDs,
 *     roughly 2.4 KB, not over a 32-byte constant with info="bench". This is
 *     the direction that matters: the old 0.187 / 0.230 ms figures are ~100x
 *     too slow for two HMAC-SHA256 invocations over 32 bytes and are almost
 *     certainly a cold first-call artefact rather than HKDF cost.
 *
 *  5. Every operation is a distribution over N windows, not one call.
 *     Gandalf/Falcon signing is rejection-sampled; its per-call latency is
 *     right-skewed with a long tail. The 1.121 ms (server) vs 3.891 ms
 *     (client) asymmetry in the current tables is one draw from that tail
 *     each, on two runs of the same code, and should not survive
 *     re-measurement as a real asymmetry.
 *
 *  6. Cycles come from perf_event_open, not from milliseconds x 3.5 GHz.
 *
 *  7. Server-side and client-side ephemeral X25519 keygen are the same
 *     function; they get one row, not two rows with different values.
 */

#define _GNU_SOURCE
#include "bench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>

#include "hdkem.h"
#include "hdkem_primitives.h"
#include "hdkem_protocol.h"
#ifdef HDKEM_WITH_OQS
#include <oqs/oqs.h>
#endif
/* The raw ML-KEM rows call liboqs directly, to separate the cryptographic
 * cost from the OQS_KEM_new()/OQS_KEM_free() pair that mlkem768_encapsulate
 * and mlkem768_decapsulate perform on every invocation. */
#ifdef HDKEM_WITH_OQS
#include <oqs/oqs.h>
#endif

/* ------------------------------------------------------------------------ *
 * Size assertions. If the project headers disagree with what the benchmark
 * assumes, fail at compile time rather than silently measuring the wrong
 * buffer sizes.
 * ------------------------------------------------------------------------ */
_Static_assert(MLKEM_PUBLIC_KEY_SIZE  == 1184, "ML-KEM-768 pk is 1184 B");
_Static_assert(MLKEM_CIPHERTEXT_SIZE  == 1088, "ML-KEM-768 ct is 1088 B");
_Static_assert(X25519_PUBLIC_KEY_SIZE == 32,   "X25519 pk is 32 B");
_Static_assert(X25519_SECRET_KEY_SIZE == 32,   "X25519 sk is 32 B");
_Static_assert(QKD_KEY_SIZE           == 32,   "k3 is 256 bit");

#define MAX3(a, b, c) ((a) > (b) ? ((a) > (c) ? (a) : (c)) : ((b) > (c) ? (b) : (c)))
#define SCRATCH_PK_SIZE \
    MAX3(MLKEM_PUBLIC_KEY_SIZE, X25519_PUBLIC_KEY_SIZE, GANDALF_PUBLIC_KEY_SIZE)
#define SCRATCH_SK_SIZE \
    MAX3(MLKEM_SECRET_KEY_SIZE, X25519_SECRET_KEY_SIZE, GANDALF_SECRET_KEY_SIZE)

/* ------------------------------------------------------------------------ *
 * Identities and message shapes, matching the protocol as implemented.
 * ------------------------------------------------------------------------ */
static const uint8_t ID_S[] = "SubstationServer001";
static const uint8_t ID_C[] = "SmartMeterClient042";
#define ID_S_LEN (sizeof ID_S - 1)
#define ID_C_LEN (sizeof ID_C - 1)

/* ------------------------------------------------------------------------ *
 * Long-lived state, set up once so the timed regions contain the primitive
 * and nothing else - no malloc, no memcpy of key material, no serialisation.
 * ------------------------------------------------------------------------ */
typedef struct {
    /* ML-KEM */
    uint8_t mlkem_pk[MLKEM_PUBLIC_KEY_SIZE];
    uint8_t mlkem_sk[MLKEM_SECRET_KEY_SIZE];
    uint8_t mlkem_ct[MLKEM_CIPHERTEXT_SIZE];
    uint8_t k1[32];

    /* X25519 */
    uint8_t xs_pk[X25519_PUBLIC_KEY_SIZE], xs_sk[X25519_SECRET_KEY_SIZE];
    uint8_t xc_pk[X25519_PUBLIC_KEY_SIZE], xc_sk[X25519_SECRET_KEY_SIZE];
    uint8_t k2[32];

    /* Gandalf ring: R = { server_pk, client_pk } */
    uint8_t gs_pk[GANDALF_PUBLIC_KEY_SIZE], gs_sk[GANDALF_SECRET_KEY_SIZE];
    uint8_t gc_pk[GANDALF_PUBLIC_KEY_SIZE], gc_sk[GANDALF_SECRET_KEY_SIZE];
    uint8_t ring_keys[2 * GANDALF_PUBLIC_KEY_SIZE];
    gandalf_ring_t ring_signer_client;   /* signer_index = 1 */
    gandalf_ring_t ring_verifier;        /* verification view              */

    /* the transcript the client signs, and a valid signature over it */
    uint8_t  tau[MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE + 2 * MAX_ID_SIZE];
    size_t   tau_len;
    uint8_t  sig[GANDALF_SIGNATURE_SIZE];

    /* QKD */
    uint8_t      k3[QKD_KEY_SIZE];
    qkd_params_t qkd;

    /* HKDF: IKM is (k1^k2^k3) || sig || c || IDc || IDs */
    uint8_t ikm[32 + GANDALF_SIGNATURE_SIZE + MLKEM_CIPHERTEXT_SIZE + 2 * MAX_ID_SIZE];
    size_t  ikm_len;
    uint8_t salt[32];
    uint8_t okm[32];

    /* AEAD */
    uint8_t ksh[32];
    uint8_t nonce[16];
    uint8_t pt[256], ct[512], tag[16];
    size_t  pt_len;

    /* Scratch for the keygen loops. Sized to the largest key of ANY scheme,
     * not to Gandalf's: ML-KEM-768 sk is 2400 B against Gandalf's 1281 B, so
     * a Gandalf-sized buffer overflows on the ML-KEM keygen row. */
    uint8_t scratch_pk[SCRATCH_PK_SIZE];
    uint8_t scratch_sk[SCRATCH_SK_SIZE];
    uint8_t ss[32];

    /* a signature that must NOT verify, for timing the reject path */
    uint8_t bad_sig[GANDALF_SIGNATURE_SIZE];

    /* bulk AEAD, for the sustained-throughput claim. The 300 Mbps figure
     * cannot be established from a 30-byte message: at that size the cost is
     * dominated by initialisation and finalisation, not by absorption. */
    uint8_t bulk_pt[65536];
    uint8_t bulk_ct[65536 + 64];
    size_t  bulk_len;

#ifdef HDKEM_WITH_OQS
    OQS_KEM *kem;      /* hoisted, so the raw rows exclude OQS_KEM_new() */
#endif
} state_t;

static state_t S;

/* ------------------------------------------------------------------------ *
 * Timed bodies. Each does exactly one primitive call.
 * ------------------------------------------------------------------------ */

static uint64_t op_mlkem_keygen(void *c) {
    (void)c; mlkem768_keypair(S.scratch_pk, S.scratch_sk); return S.scratch_pk[0];
}
static uint64_t op_x25519_keygen(void *c) {
    (void)c; x25519_keypair(S.scratch_pk, S.scratch_sk); return S.scratch_pk[0];
}
static uint64_t op_gandalf_keygen(void *c) {
    (void)c; gandalf_keypair(S.scratch_pk, S.scratch_sk); return S.scratch_pk[0];
}
static uint64_t op_mlkem_encaps(void *c) {
    (void)c; mlkem768_encapsulate(S.mlkem_pk, S.ct, S.ss); return S.ss[0];
}
static uint64_t op_mlkem_decaps(void *c) {
    (void)c; mlkem768_decapsulate(S.mlkem_sk, S.mlkem_ct, S.ss); return S.ss[0];
}
static uint64_t op_x25519_dh(void *c) {
    (void)c; x25519_shared_secret(S.xc_sk, S.xs_pk, S.ss); return S.ss[0];
}
static uint64_t op_gandalf_sign(void *c) {
    (void)c;
    gandalf_sign(S.gc_sk, S.tau, S.tau_len, &S.ring_signer_client, S.sig);
    return S.sig[0];
}
static uint64_t op_gandalf_verify(void *c) {
    (void)c;
    int rc = gandalf_verify(S.tau, S.tau_len, S.sig, &S.ring_verifier);
    /* If this ever becomes non-zero the reject path is being timed, which is
     * exactly the defect this rewrite exists to remove. */
    if (rc != 0) { fprintf(stderr, "FATAL: verify failed inside timed loop\n"); exit(2); }
    return (uint64_t)rc;
}
static uint64_t op_hkdf(void *c) {
    (void)c;
    hkdf(S.salt, sizeof S.salt, S.ikm, S.ikm_len,
         (const uint8_t *)"HDKEM-v1", 8, S.okm, sizeof S.okm);
    return S.okm[0];
}
static uint64_t op_qkd(void *c) {
    /* The implementation mutates the qkd_params_t it is handed (observed:
     * distance 50 km -> 1.25e171 -> 0, QBER 4% -> 0%). Handing it a fresh
     * copy each call keeps every timed iteration on the configuration the
     * table names, instead of the first call measuring 50 km / 4% and every
     * later one measuring 0 km / 0%, which takes a different path through
     * the regime selector. The struct copy is ~24 bytes against a ~64 us
     * operation. This contains the symptom; see qkd_probe.c for the cause. */
    (void)c;
    qkd_params_t p = S.qkd;
    qkd_establish_key(&p, S.k3, QKD_KEY_SIZE);
    return S.k3[0];
}
/* Reject path, timed deliberately and labelled as such. The previous driver
 * timed this by accident (verify over a 4-byte buffer with |R| = 1, annotated
 * "will fail but is fast") and reported it as verification cost. Measuring
 * both paths turns that into a quantified statement instead of an assertion. */
static uint64_t op_gandalf_verify_reject(void *c) {
    (void)c;
    int rc = gandalf_verify(S.tau, S.tau_len, S.bad_sig, &S.ring_verifier);
    if (rc == 0) { fprintf(stderr, "FATAL: tampered signature verified\n"); exit(2); }
    return (uint64_t)rc;
}
static uint64_t op_ascon_enc_bulk(void *c) {
    (void)c;
    ascon_encrypt(S.ksh, S.nonce, S.bulk_pt, S.bulk_len, NULL, 0, S.bulk_ct, S.tag);
    return S.bulk_ct[0];
}
#ifdef HDKEM_WITH_OQS
/* mlkem768_encapsulate/decapsulate call OQS_KEM_new() and OQS_KEM_free() on
 * every invocation, so the wrapper rows include an allocation and an algorithm
 * lookup that no deployment would pay per handshake. mlkem768_keypair was
 * NOT measured through the wrapper in the old driver (it used a hoisted
 * OQS_KEM object), so Table 4's keygen and encaps/decaps rows are on different
 * baselines. These rows separate the two. */
static uint64_t op_mlkem_keygen_raw(void *c) {
    (void)c; OQS_KEM_keypair(S.kem, S.scratch_pk, S.scratch_sk); return S.scratch_pk[0];
}
static uint64_t op_mlkem_encaps_raw(void *c) {
    (void)c; OQS_KEM_encaps(S.kem, S.ct, S.ss, S.mlkem_pk); return S.ss[0];
}
static uint64_t op_mlkem_decaps_raw(void *c) {
    (void)c; OQS_KEM_decaps(S.kem, S.ss, S.mlkem_ct, S.mlkem_sk); return S.ss[0];
}
#endif
static uint64_t op_ascon_enc(void *c) {
    (void)c;
    ascon_encrypt(S.ksh, S.nonce, S.pt, S.pt_len, NULL, 0, S.ct, S.tag);
    return S.ct[0];
}
static uint64_t op_ascon_dec(void *c) {
    (void)c;
    uint8_t out[256];
    ascon_decrypt(S.ksh, S.nonce, S.ct, S.pt_len, NULL, 0, S.tag, out);
    return out[0];
}

/* ------------------------------------------------------------------------ *
 * Setup
 * ------------------------------------------------------------------------ */
static void setup(void)
{
    memset(&S, 0, sizeof S);

    if (mlkem768_keypair(S.mlkem_pk, S.mlkem_sk) != 0) { fputs("mlkem keygen\n", stderr); exit(1); }
    if (x25519_keypair(S.xs_pk, S.xs_sk)        != 0) { fputs("x25519 srv\n",   stderr); exit(1); }
    if (x25519_keypair(S.xc_pk, S.xc_sk)        != 0) { fputs("x25519 cli\n",   stderr); exit(1); }
    if (gandalf_keypair(S.gs_pk, S.gs_sk)       != 0) { fputs("gandalf srv\n",  stderr); exit(1); }
    if (gandalf_keypair(S.gc_pk, S.gc_sk)       != 0) { fputs("gandalf cli\n",  stderr); exit(1); }

    /* a real ciphertext for decapsulation */
    mlkem768_encapsulate(S.mlkem_pk, S.mlkem_ct, S.k1);
    x25519_shared_secret(S.xc_sk, S.xs_pk, S.k2);

    S.qkd.distance_km = 50.0;
    S.qkd.qber        = 0.04;
    S.qkd.efficiency  = 0.90;
    qkd_establish_key(&S.qkd, S.k3, QKD_KEY_SIZE);

    /* ring R = { server, client }, client is index 1 */
    memcpy(S.ring_keys,                           S.gs_pk, GANDALF_PUBLIC_KEY_SIZE);
    memcpy(S.ring_keys + GANDALF_PUBLIC_KEY_SIZE, S.gc_pk, GANDALF_PUBLIC_KEY_SIZE);
    S.ring_signer_client.ring_public_keys = S.ring_keys;
    S.ring_signer_client.ring_size        = 2;
    S.ring_signer_client.signer_index     = 1;
    S.ring_verifier = S.ring_signer_client;

    /* transcript tau = c || pk_r2 || IDs || IDc   (public transcript only) */
    {
        size_t o = 0;
        memcpy(S.tau + o, S.mlkem_ct, MLKEM_CIPHERTEXT_SIZE);  o += MLKEM_CIPHERTEXT_SIZE;
        memcpy(S.tau + o, S.xc_pk,    X25519_PUBLIC_KEY_SIZE); o += X25519_PUBLIC_KEY_SIZE;
        memcpy(S.tau + o, ID_S,       ID_S_LEN);               o += ID_S_LEN;
        memcpy(S.tau + o, ID_C,       ID_C_LEN);               o += ID_C_LEN;
        S.tau_len = o;
    }

    /* one valid signature, reused by the verify loop */
    if (gandalf_sign(S.gc_sk, S.tau, S.tau_len, &S.ring_signer_client, S.sig) != 0) {
        fputs("gandalf sign failed during setup\n", stderr); exit(1);
    }
    if (gandalf_verify(S.tau, S.tau_len, S.sig, &S.ring_verifier) != 0) {
        fputs("setup signature does not verify - ring convention mismatch\n", stderr);
        exit(1);
    }

    /* IKM = (k1^k2^k3) || sig || c || IDc || IDs */
    {
        size_t o = 0;
        for (int i = 0; i < 32; i++) S.ikm[o + i] = S.k1[i] ^ S.k2[i] ^ S.k3[i];
        o += 32;
        memcpy(S.ikm + o, S.sig,      GANDALF_SIGNATURE_SIZE); o += GANDALF_SIGNATURE_SIZE;
        memcpy(S.ikm + o, S.mlkem_ct, MLKEM_CIPHERTEXT_SIZE);  o += MLKEM_CIPHERTEXT_SIZE;
        memcpy(S.ikm + o, ID_C,       ID_C_LEN);               o += ID_C_LEN;
        memcpy(S.ikm + o, ID_S,       ID_S_LEN);               o += ID_S_LEN;
        S.ikm_len = o;
    }

    hkdf(S.salt, sizeof S.salt, S.ikm, S.ikm_len,
         (const uint8_t *)"HDKEM-v1", 8, S.ksh, sizeof S.ksh);

    random_bytes(S.nonce, sizeof S.nonce);

    /* tampered copy: must fail verification, checked here not in the loop */
    memcpy(S.bad_sig, S.sig, GANDALF_SIGNATURE_SIZE);
    S.bad_sig[GANDALF_SIGNATURE_SIZE / 2] ^= 0x01;
    if (gandalf_verify(S.tau, S.tau_len, S.bad_sig, &S.ring_verifier) == 0) {
        fputs("setup: tampered signature still verifies - "
              "gandalf_verify is not checking what it should\n", stderr);
        exit(1);
    }

    random_bytes(S.bulk_pt, sizeof S.bulk_pt);

#ifdef HDKEM_WITH_OQS
    S.kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!S.kem) { fputs("OQS_KEM_new failed\n", stderr); exit(1); }
#endif

    /* Consistency check on k3. qkd_establish_key seeds libc srand() and draws
     * from rand(); if it is reseeded per call from a coarse clock, every k3 in
     * a benchmark loop is identical. That does not affect the timing rows, but
     * it does affect every security claim made about k3, so it is surfaced. */
    {
        uint8_t a[QKD_KEY_SIZE], b[QKD_KEY_SIZE];
        qkd_params_t pa = S.qkd, pb = S.qkd;
        qkd_establish_key(&pa, a, QKD_KEY_SIZE);
        qkd_establish_key(&pb, b, QKD_KEY_SIZE);
        if (memcmp(a, b, QKD_KEY_SIZE) == 0)
            fputs("[bench] WARNING: qkd_establish_key returned identical keys on\n"
                  "        two consecutive calls. k3 is not fresh per session.\n",
                  stderr);
    }

    /* Does qkd_establish_key write past the end of the key buffer? A guarded
     * region answers this without a sanitiser build. If the trailing guard is
     * clobbered, the adjacent field in any caller's struct is being
     * overwritten, which is what corrupted the parameters in earlier runs. */
    {
        uint8_t region[64 + QKD_KEY_SIZE + 64];
        memset(region, 0xA5, sizeof region);
        qkd_params_t p = S.qkd;
        qkd_establish_key(&p, region + 64, QKD_KEY_SIZE);
        for (size_t i = 64 + QKD_KEY_SIZE; i < sizeof region; i++)
            if (region[i] != 0xA5) {
                fprintf(stderr,
                    "[bench] WARNING: qkd_establish_key wrote %zu bytes past the\n"
                    "        end of a %d-byte key buffer. This is a memory-safety\n"
                    "        bug, not a benchmarking artefact. Run qkd_probe.c\n"
                    "        under ASan before using any QKD figure.\n",
                    i - (64 + QKD_KEY_SIZE) + 1, QKD_KEY_SIZE);
                break;
            }
        if (p.distance_km != S.qkd.distance_km || p.qber != S.qkd.qber)
            fputs("[bench] WARNING: qkd_establish_key mutated the parameter\n"
                  "        struct it was given. Timed calls now use a private\n"
                  "        copy, so the rows stay on the named configuration.\n",
                  stderr);
    }
}

/* ------------------------------------------------------------------------ *
 * Table 7: per-protocol AEAD cost at the real payload sizes.
 * Payload lengths are taken from the message constructors in hdkem_client.c
 * rather than from the current Table 7, which lists 42 B for IEC 61850 and
 * 45 B for C37.118.2 while the constructors build 27 B and 51 B payloads.
 * ------------------------------------------------------------------------ */
typedef struct { const char *name; const char *payload; } proto_case_t;

static const proto_case_t PROTOCOLS[] = {
    { "ANSI C12.22",    "TABLE_23_READ:TOTAL_ENERGY_KWH" },
    { "DNP3",           "OBJ_01_VAR_02:BREAKER_STATUS=CLOSED" },
    { "IEC 61850",      "GET_VAR:TOTAL_WATTS=15234.5" },
    { "IEEE C37.118.2", "PHASOR:V=120.0V,ANG=0.0,FREQ=60.00Hz,ROCOF=0.01Hz/s" },
};
#define N_PROTOCOLS (sizeof PROTOCOLS / sizeof PROTOCOLS[0])

/* ------------------------------------------------------------------------ */

static void pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0)
        fprintf(stderr, "[bench] warning: could not pin to cpu %d\n", cpu);
}

int main(int argc, char **argv)
{
    size_t outer     = BENCH_DEFAULT_OUTER;
    size_t sig_outer = 0;              /* signing is ~4 ms; allow a smaller N */
    int    cpu       = 0;
    const char *csv_path = "hdkem_bench.csv";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-n")   && i + 1 < argc) outer     = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-s")   && i + 1 < argc) sig_outer = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-c")   && i + 1 < argc) cpu       = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-o")   && i + 1 < argc) csv_path  = argv[++i];
        else {
            fprintf(stderr,
                "usage: %s [-n windows] [-s sign_windows] [-c cpu] [-o out.csv]\n",
                argv[0]);
            return 1;
        }
    }
    if (sig_outer == 0) sig_outer = outer;

    pin_cpu(cpu);
    bench_init();

    printf("HDKEM microbenchmark\n\n");
    bench_print_environment(stdout);

    setup();

    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    bench_csv_header(csv);

    bench_result_t r[48];
    size_t k = 0;

    printf("Key generation and handshake primitives\n");
    bench_print_header();

    struct { const char *n; const char *role; bench_fn fn; size_t N; } ops[] = {
        { "MLKEM768.KeyGen",   "-",   op_mlkem_keygen,   outer     },
        { "X25519.KeyGen",     "-",   op_x25519_keygen,  outer     },
        { "Gandalf.KeyGen",    "-",   op_gandalf_keygen, sig_outer },
        { "MLKEM768.Encaps",   "Cli", op_mlkem_encaps,   outer     },
        { "MLKEM768.Decaps",   "Srv", op_mlkem_decaps,   outer     },
        { "X25519.DH",         "-",   op_x25519_dh,      outer     },
        { "Gandalf.RingSign",  "Cli", op_gandalf_sign,   sig_outer },
        { "Gandalf.RingVerify","Srv", op_gandalf_verify, outer     },
        { "HKDF",              "-",   op_hkdf,           outer     },
        { "QKD.Establish",     "-",   op_qkd,            outer     },
    };

    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        r[k] = bench_run(ops[i].n, ops[i].role, ops[i].fn, NULL,
                         ops[i].N, ops[i].fn, NULL);
        bench_print(&r[k]);
        bench_csv_row(csv, &r[k]);
        k++;
    }

    printf("\nAEAD cost by smart grid protocol payload\n");
    bench_print_header();

    static char enc_names[N_PROTOCOLS][64];
    static char dec_names[N_PROTOCOLS][64];

    for (size_t i = 0; i < N_PROTOCOLS; i++) {
        S.pt_len = strlen(PROTOCOLS[i].payload);
        memcpy(S.pt, PROTOCOLS[i].payload, S.pt_len);
        ascon_encrypt(S.ksh, S.nonce, S.pt, S.pt_len, NULL, 0, S.ct, S.tag);

        snprintf(enc_names[i], sizeof enc_names[i], "Ascon.Enc %s (%zuB)",
                 PROTOCOLS[i].name, S.pt_len);
        snprintf(dec_names[i], sizeof dec_names[i], "Ascon.Dec %s (%zuB)",
                 PROTOCOLS[i].name, S.pt_len);

        r[k] = bench_run(enc_names[i], "-", op_ascon_enc, NULL, outer, NULL, NULL);
        bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;

        r[k] = bench_run(dec_names[i], "-", op_ascon_dec, NULL, outer, NULL, NULL);
        bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;
    }

    /* --------------------------------------------------------------------
     * Diagnostics. These rows are not paper rows; they exist to quantify the
     * gap between what the previous driver measured and what the protocol
     * costs, so the revision can state the delta rather than assert it.
     * -------------------------------------------------------------------- */
    printf("\nDiagnostics (not paper rows)\n");
    bench_print_header();

    {
        size_t tau_real = S.tau_len;

        /* (a) signing a 32-byte dummy, as the old client driver did */
        S.tau_len = 32;
        gandalf_sign(S.gc_sk, S.tau, S.tau_len, &S.ring_signer_client, S.sig);
        r[k] = bench_run("Gandalf.RingSign [32B dummy]", "Cli",
                         op_gandalf_sign, NULL, sig_outer, NULL, NULL);
        bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;

        /* restore the real transcript and its valid signature */
        S.tau_len = tau_real;
        gandalf_sign(S.gc_sk, S.tau, S.tau_len, &S.ring_signer_client, S.sig);
        memcpy(S.bad_sig, S.sig, GANDALF_SIGNATURE_SIZE);
        S.bad_sig[GANDALF_SIGNATURE_SIZE / 2] ^= 0x01;

        /* (b) the reject path, which the old driver timed as "verify" */
        r[k] = bench_run("Gandalf.RingVerify [reject path]", "Srv",
                         op_gandalf_verify_reject, NULL, outer, NULL, NULL);
        bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;

        /* (c) HKDF over 32 bytes, as the old driver did, vs the real IKM */
        size_t ikm_real = S.ikm_len;
        S.ikm_len = 32;
        r[k] = bench_run("HKDF [32B IKM legacy]", "-", op_hkdf, NULL, outer, NULL, NULL);
        bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;
        S.ikm_len = ikm_real;
    }

#ifdef HDKEM_WITH_OQS
    {
        struct { const char *n; bench_fn fn; } raw[] = {
            { "MLKEM768.KeyGen [no OQS_KEM_new]", op_mlkem_keygen_raw },
            { "MLKEM768.Encaps [no OQS_KEM_new]", op_mlkem_encaps_raw },
            { "MLKEM768.Decaps [no OQS_KEM_new]", op_mlkem_decaps_raw },
        };
        for (size_t i = 0; i < sizeof raw / sizeof raw[0]; i++) {
            r[k] = bench_run(raw[i].n, "-", raw[i].fn, NULL, outer, NULL, NULL);
            bench_print(&r[k]); bench_csv_row(csv, &r[k]); k++;
        }
    }
#endif

    /* --------------------------------------------------------------------
     * Sustained AEAD throughput. The 300 Mbps claim needs bulk data; a 30-byte
     * message measures permutation setup, not steady-state absorption rate.
     * -------------------------------------------------------------------- */
    printf("\nAscon-128a sustained throughput\n");
    printf("%-30s %10s %12s\n", "payload", "med(ms)", "Mbit/s");
    printf("%-30s %10s %12s\n", "------------------------------",
           "---------", "-----------");

    {
        static const size_t sizes[] = { 256, 1024, 4096, 16384, 65536 };
        static char tn[sizeof sizes / sizeof sizes[0]][48];
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            S.bulk_len = sizes[i];
            snprintf(tn[i], sizeof tn[i], "Ascon.Enc bulk (%zuB)", sizes[i]);
            r[k] = bench_run(tn[i], "-", op_ascon_enc_bulk, NULL,
                             outer < 2000 ? outer : 2000, NULL, NULL);
            double ms   = r[k].ns_median / 1e6;
            double mbps = (double)sizes[i] * 8.0 / r[k].ns_median * 1000.0;
            printf("%-30s %10.5f %12.1f\n", tn[i], ms, mbps);
            bench_csv_row(csv, &r[k]);
            k++;
        }
        printf("  Quote the asymptote, not the 45-byte figure, for a "
               "throughput claim.\n");
    }

    fclose(csv);

    /* --------------------------------------------------------------------
     * Wire sizes, computed from the same constants the code uses rather than
     * transcribed by hand, so Table 8 cannot drift away from the build.
     * -------------------------------------------------------------------- */
    printf("\nHandshake size accounting (from build-time constants)\n");
    printf("  ML-KEM-768 public key          %6d B\n", MLKEM_PUBLIC_KEY_SIZE);
    printf("  ML-KEM-768 ciphertext          %6d B\n", MLKEM_CIPHERTEXT_SIZE);
    printf("  X25519 public key              %6d B\n", X25519_PUBLIC_KEY_SIZE);
    printf("  Gandalf ring public key        %6d B\n", GANDALF_PUBLIC_KEY_SIZE);
    printf("  Gandalf ring signature         %6d B\n", GANDALF_SIGNATURE_SIZE);
    printf("  QKD key k3 (not transmitted)   %6d B\n", QKD_KEY_SIZE);
    printf("  signed transcript tau          %6zu B\n", S.tau_len);
    printf("  KDF input keying material      %6zu B\n", S.ikm_len);
    printf("  ---------------------------------------\n");
    printf("  server -> client (pk1+pk2)     %6d B\n",
           MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);
    printf("  client -> server (c+pk+sig)    %6d B\n",
           MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE + GANDALF_SIGNATURE_SIZE);
    printf("  total handshake bytes on wire  %6d B\n",
           MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE +
           MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE + GANDALF_SIGNATURE_SIZE);
    printf("  (excludes ring public key distribution, which is provisioning-\n"
           "   time and should be stated separately rather than folded in)\n");

    /* --------------------------------------------------------------------
     * Handshake composition.
     *
     * The per-role totals are the sum of the measured medians of the
     * operations that role actually performs, printed alongside the
     * composition so the arithmetic is checkable. The current Table 5 sums
     * to 1.707 ms from its own rows but reports 1.807 ms, and Table 6 sums
     * to 5.331 ms from its rows but reports 5.015 ms; in both cases some
     * rows are nested inside others and are being counted twice.
     * -------------------------------------------------------------------- */
    printf("\nHandshake composition (sum of measured medians, ms)\n");
    printf("  Reported here as arithmetic over the rows above. Sub-operations\n"
           "  are never also counted inside an aggregate row.\n\n");

    double med[48];
    for (size_t i = 0; i < k; i++) med[i] = r[i].ns_median / 1e6;

    enum { MLKEM_KG, X_KG, G_KG, MLKEM_ENC, MLKEM_DEC, X_DH, G_SIGN, G_VRFY, HKDF_, QKD_ };

    double srv = med[MLKEM_KG] + med[X_KG] + med[G_VRFY] + med[MLKEM_DEC]
               + med[X_DH] + med[HKDF_] + med[QKD_];
    double cli = med[X_KG] + med[MLKEM_ENC] + med[X_DH] + med[G_SIGN]
               + med[HKDF_] + med[QKD_];

    printf("  Server: MLKEM.KeyGen %.4f + X25519.KeyGen %.4f + RingVerify %.4f\n"
           "        + MLKEM.Decaps %.4f + X25519.DH %.4f + HKDF %.4f + QKD %.4f\n"
           "        = %.4f ms\n\n",
           med[MLKEM_KG], med[X_KG], med[G_VRFY], med[MLKEM_DEC],
           med[X_DH], med[HKDF_], med[QKD_], srv);

    printf("  Client: X25519.KeyGen %.4f + MLKEM.Encaps %.4f + X25519.DH %.4f\n"
           "        + RingSign %.4f + HKDF %.4f + QKD %.4f\n"
           "        = %.4f ms\n\n",
           med[X_KG], med[MLKEM_ENC], med[X_DH],
           med[G_SIGN], med[HKDF_], med[QKD_], cli);

    printf("  Core crypto only (Encaps + DH + HKDF), client: %.4f ms\n",
           med[MLKEM_ENC] + med[X_DH] + med[HKDF_]);
    printf("  Ring signature share of client handshake:      %.1f%%\n",
           100.0 * med[G_SIGN] / cli);
    printf("  Gandalf.KeyGen amortised over 10k sessions:    %.6f ms/session\n",
           med[G_KG] / 10000.0);

    printf("\n  Signing tail (rejection sampling): median %.4f  p95 %.4f  max %.4f ms\n",
           r[G_SIGN].ns_median / 1e6, r[G_SIGN].ns_p95 / 1e6, r[G_SIGN].ns_max / 1e6);
    printf("  Report the median with its p05-p95 range; a single draw from this\n"
           "  distribution is not a protocol figure.\n");

    printf("\nRaw per-window samples written to %s\n", csv_path);

    for (size_t i = 0; i < k; i++) bench_free(&r[i]);
    bench_shutdown();
    return 0;
}
