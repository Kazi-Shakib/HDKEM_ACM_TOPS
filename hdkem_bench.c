#include "hdkem_wire.h"

#include <sched.h>

#ifndef BENCH_N
#define BENCH_N 2000u
#endif

static const uint8_t ID_S[] = "SubstationServer001";
static const uint8_t ID_C[] = "SmartMeterClient042";
#define ID_S_LEN (sizeof ID_S - 1u)
#define ID_C_LEN (sizeof ID_C - 1u)
static const char LABEL_S[] = "HDKEM-v1-server-finished";
static const char LABEL_C[] = "HDKEM-v1-client-finished";

typedef uint64_t (*bench_fn)(void *);

static void pin_core0(void)
{
#ifdef __linux__
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
    (void)sched_setaffinity(0, sizeof set, &set);
#endif
}

static void report_fn(const char *name, bench_fn fn, void *ctx, size_t n)
{
    uint64_t *s = calloc(n, sizeof *s);
    if (!s) exit(1);
    volatile uint64_t sink = 0;
    for (size_t i=0;i<n;i++) {
        uint64_t t0=hdkem_now_ns(); sink ^= fn(ctx); s[i]=hdkem_now_ns()-t0;
    }
    (void)sink;
    hdkem_report(name,s,n); free(s);
}

typedef struct {
    uint8_t ml_pk[MLKEM_PUBLIC_KEY_SIZE], ml_sk[MLKEM_SECRET_KEY_SIZE], ct[MLKEM_CIPHERTEXT_SIZE];
    uint8_t xs_pk[32], xs_sk[32], xc_pk[32], xc_sk[32];
    uint8_t gs_pk[HDKEM_MAX_RS_PUBLIC_KEY_SIZE], gs_sk[HDKEM_MAX_RS_SECRET_KEY_SIZE];
    uint8_t gc_pk[HDKEM_MAX_RS_PUBLIC_KEY_SIZE], gc_sk[HDKEM_MAX_RS_SECRET_KEY_SIZE];
    uint8_t ring_keys[2u * HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
    gandalf_ring_t signer, verifier;
    uint8_t k1[32],k2[32],k3[48],kid[HDKEM_SOURCE_ID_BYTES],master[HDKEM_SOURCE_MASTER_BYTES];
    uint8_t tau[HDKEM_MAX_TAU]; size_t tau_len;
    uint8_t sig[HDKEM_MAX_SIGNATURE_SIZE], okm[96];
    uint8_t nonce[16], tag[16], pt[64], ct_aead[64];
} state_t;

static state_t S;
static size_t BENCH_SOURCE_BYTES = 32u; /* paper measured configuration */
static rs_scheme_t BENCH_SCHEME = RS_SCHEME_GANDALF;

static uint64_t b_mlkg(void *x){(void)x; uint8_t p[MLKEM_PUBLIC_KEY_SIZE],s[MLKEM_SECRET_KEY_SIZE]; return (uint64_t)mlkem768_keypair(p,s);}
static uint64_t b_mlen(void *x){(void)x; uint8_t ss[32],ct[MLKEM_CIPHERTEXT_SIZE]; return (uint64_t)mlkem768_encapsulate(S.ml_pk,ct,ss);}
static uint64_t b_mlde(void *x){(void)x; uint8_t ss[32]; return (uint64_t)mlkem768_decapsulate(S.ml_sk,S.ct,ss);}
static uint64_t b_xkg(void *x){(void)x; uint8_t p[32],s[32]; return (uint64_t)x25519_keypair(p,s);}
static uint64_t b_xdh(void *x){(void)x; uint8_t ss[32]; return (uint64_t)x25519_shared_secret(S.xc_sk,S.xs_pk,ss);}
static uint64_t b_gkg(void *x){
    (void)x;
    uint8_t p[HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
    uint8_t s[HDKEM_MAX_RS_SECRET_KEY_SIZE];
    return (uint64_t)rs_keypair(BENCH_SCHEME,p,s);
}
static uint64_t b_gsign(void *x){(void)x; return (uint64_t)rs_sign(BENCH_SCHEME,S.gc_sk,S.tau,S.tau_len,&S.signer,S.sig);}
static uint64_t b_gver(void *x){
    (void)x;
    int rc=rs_verify(BENCH_SCHEME,S.tau,S.tau_len,S.sig,&S.verifier);
    if(rc){fprintf(stderr,"valid %s signature rejected\n",rs_scheme_name(BENCH_SCHEME));exit(2);}
    return 0;
}
static uint64_t b_src(void *x){
    (void)x;
    return (uint64_t)hdkem_source_derive(S.master,S.kid,S.k3,BENCH_SOURCE_BYTES);
}
static uint64_t b_prf(void *x){
    (void)x;
    return (uint64_t)hdkem_skprf(S.k1,32,S.k2,32,S.k3,BENCH_SOURCE_BYTES,
                                  S.tau,S.tau_len,S.okm,64);
}
static uint64_t b_aead(void *x){
    (void)x;
    uint8_t key[HDKEM_AEAD_KEY_BYTES];
    hdkem_ascon_key(key,S.okm);
    int rc=ascon_encrypt(key,S.nonce,S.pt,sizeof S.pt,NULL,0,S.ct_aead,S.tag);
    sodium_memzero(key,sizeof key);
    return (uint64_t)rc;
}

static int setup(void)
{
    if (sodium_init()<0) return -1;
    if (mlkem768_keypair(S.ml_pk,S.ml_sk) || mlkem768_encapsulate(S.ml_pk,S.ct,S.k1)) return -1;
    if (x25519_keypair(S.xs_pk,S.xs_sk) || x25519_keypair(S.xc_pk,S.xc_sk) ||
        x25519_shared_secret(S.xc_sk,S.xs_pk,S.k2)) return -1;
    if (rs_keypair(BENCH_SCHEME,S.gs_pk,S.gs_sk) || rs_keypair(BENCH_SCHEME,S.gc_pk,S.gc_sk)) return -1;
    const size_t rs_pk_len = rs_public_key_size(BENCH_SCHEME);
    memcpy(S.ring_keys, S.gs_pk, rs_pk_len);
    memcpy(S.ring_keys + rs_pk_len, S.gc_pk, rs_pk_len);
    S.signer=(gandalf_ring_t){S.ring_keys,2,1}; S.verifier=S.signer;
    randombytes_buf(S.master,sizeof S.master); randombytes_buf(S.kid,sizeof S.kid);
    if (hdkem_source_derive(S.master,S.kid,S.k3,BENCH_SOURCE_BYTES)) return -1;
    S.tau_len=hdkem_build_tau(S.tau,sizeof S.tau,S.ml_pk,S.ct,S.xc_pk,S.xs_pk,
                              ID_C,ID_C_LEN,ID_S,ID_S_LEN,HDKEM_MODE_SRC,S.kid,sizeof S.kid);
    if(!S.tau_len || rs_sign(BENCH_SCHEME,S.gc_sk,S.tau,S.tau_len,&S.signer,S.sig)) return -1;
    if(hdkem_skprf(S.k1,32,S.k2,32,S.k3,BENCH_SOURCE_BYTES,
                     S.tau,S.tau_len,S.okm,64)) return -1;
    randombytes_buf(S.nonce,sizeof S.nonce); randombytes_buf(S.pt,sizeof S.pt);
    return 0;
}

int main(int argc,char **argv)
{
    size_t n=BENCH_N;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-n") && i+1<argc) n=strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"-b") && i+1<argc) BENCH_SOURCE_BYTES=strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"-r") && i+1<argc) {
            if (rs_scheme_from_name(argv[++i], &BENCH_SCHEME)) {
                fprintf(stderr,"-r must be gandalf or falconrs\n"); return 1;
            }
        }
        else if(argv[i][0]!='-' && i==1) n=strtoul(argv[i],NULL,10);
        else {
            fprintf(stderr,"usage: %s [-n reps] [-b 32|48] [-r gandalf|falconrs]\n",argv[0]);
            return 1;
        }
    }
    if(BENCH_SOURCE_BYTES!=32u && BENCH_SOURCE_BYTES!=48u){
        fprintf(stderr,"-b must be 32 or 48\n");
        return 1;
    }
    pin_core0(); if(setup()){fprintf(stderr,"setup failed\n");return 1;}
    printf("HDKEM artifact v%u microbench, n=%zu, source=%zu B, scheme=%s\n",
           HDKEM_ARTIFACT_VERSION,n,BENCH_SOURCE_BYTES,rs_scheme_name(BENCH_SCHEME));
    report_fn("ML-KEM keygen",b_mlkg,NULL,n);
    report_fn("ML-KEM encaps",b_mlen,NULL,n);
    report_fn("ML-KEM decaps",b_mlde,NULL,n);
    report_fn("X25519 keygen",b_xkg,NULL,n);
    report_fn("X25519 DH",b_xdh,NULL,n);
    { char lbl[32];
      snprintf(lbl,sizeof lbl,"%s keygen",rs_scheme_name(BENCH_SCHEME)); report_fn(lbl,b_gkg,NULL,n);
      snprintf(lbl,sizeof lbl,"%s sign",rs_scheme_name(BENCH_SCHEME)); report_fn(lbl,b_gsign,NULL,n);
      snprintf(lbl,sizeof lbl,"%s verify(valid)",rs_scheme_name(BENCH_SCHEME)); report_fn(lbl,b_gver,NULL,n);
    }
    report_fn("Src.GetWithID derive",b_src,NULL,n);
    report_fn("split-key PRF",b_prf,NULL,n);
    report_fn("Ascon-128a op",b_aead,NULL,n);

    puts("\nExact source-mode wire accounting (paper Finished = AEAD(label||tau)):");
    hdkem_wire_account_t a=hdkem_expected_wire(ID_C_LEN,ID_S_LEN,HDKEM_MODE_SRC,strlen(LABEL_S),strlen(LABEL_C),BENCH_SCHEME);
    hdkem_print_wire_account(&a);
    printf("  tau                             %zu B\n",hdkem_tau_size(ID_C_LEN,ID_S_LEN,HDKEM_MODE_SRC));
    printf("  %-8s signature               %zu B\n",rs_scheme_name(BENCH_SCHEME),rs_signature_size(BENCH_SCHEME));
    printf("\nNote: the two Finished ciphertexts each carry label||tau; this is why\n"
           "the end-to-end wire total is much larger than the one-flight crypto-only\n"
           "sum. Ring verification keys are not transmitted by these endpoints.\n");
    return 0;
}
