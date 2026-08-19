#include "hdkem_wire.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define SRV_RSK "server.rsk"
#define SRV_RVK "server.rvk"
#define CLI_RVK "client.rvk"

static const uint8_t ID_S[] = "SubstationServer001";
static const uint8_t ID_C[] = "SmartMeterClient042";
#define ID_S_LEN (sizeof ID_S - 1u)
#define ID_C_LEN (sizeof ID_C - 1u)

static const char LABEL_S[] = "HDKEM-v1-server-finished";
static const char LABEL_C[] = "HDKEM-v1-client-finished";

typedef struct {
    uint64_t *keygen, *verify, *decaps, *dh, *source, *skprf, *aead, *total;
    size_t n;
} srv_samples_t;

static int build_finished(uint8_t *frame, size_t cap, size_t *out_len,
                          const uint8_t *kcf, const char *label,
                          const uint8_t *tau, size_t tau_len)
{
    size_t lab = strlen(label), pt_len = lab + tau_len;
    if (HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES + pt_len > cap) return -1;
    uint8_t *pt = malloc(pt_len ? pt_len : 1);
    if (!pt) return -1;
    memcpy(pt, label, lab); memcpy(pt + lab, tau, tau_len);
    uint8_t *nu = frame;
    uint8_t *tag = frame + HDKEM_AEAD_NONCE_BYTES;
    uint8_t *ct = frame + HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES;
    randombytes_buf(nu, HDKEM_AEAD_NONCE_BYTES);
    uint8_t aead_key[HDKEM_AEAD_KEY_BYTES];
    hdkem_ascon_key(aead_key, kcf);
    int rc = ascon_encrypt(aead_key, nu, pt, pt_len, NULL, 0, ct, tag);
    sodium_memzero(aead_key, sizeof aead_key);
    sodium_memzero(pt, pt_len); free(pt);
    if (rc) return -1;
    *out_len = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES + pt_len;
    return 0;
}

static int verify_finished(const uint8_t *frame, size_t n,
                           const uint8_t *kcf, const char *label,
                           const uint8_t *tau, size_t tau_len)
{
    size_t fixed = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES;
    size_t lab = strlen(label);
    if (n != fixed + lab + tau_len) return -1;
    uint8_t *pt = malloc(lab + tau_len);
    if (!pt) return -1;
    const uint8_t *nu = frame;
    const uint8_t *tag = frame + HDKEM_AEAD_NONCE_BYTES;
    const uint8_t *ct = frame + fixed;
    uint8_t aead_key[HDKEM_AEAD_KEY_BYTES];
    hdkem_ascon_key(aead_key, kcf);
    int rc = ascon_decrypt(aead_key, nu, ct, lab + tau_len,
                           NULL, 0, tag, pt);
    sodium_memzero(aead_key, sizeof aead_key);
    if (!rc && (memcmp(pt, label, lab) || memcmp(pt + lab, tau, tau_len))) rc = -1;
    sodium_memzero(pt, lab + tau_len); free(pt);
    return rc;
}

static int serve_one(int fd, const hdkem_ring_t *ring, const uint8_t *rskS,
                     const uint8_t source_master[HDKEM_SOURCE_MASTER_BYTES],
                     hdkem_mode_t mode, size_t source_bytes, rs_scheme_t scheme,
                     srv_samples_t *S, size_t i, size_t *payload_wire)
{
    uint8_t frame[HDKEM_MAX_FRAME], tau[HDKEM_MAX_TAU];
    uint8_t pkS1[MLKEM_PUBLIC_KEY_SIZE], skS1[MLKEM_SECRET_KEY_SIZE];
    uint8_t pkS2[X25519_PUBLIC_KEY_SIZE], skS2[X25519_SECRET_KEY_SIZE];
    uint8_t k1[32], k2[32], k3[HDKEM_SOURCE_MAX_BYTES], okm[96];
    uint64_t all0 = hdkem_now_ns(), t0;
    size_t wire = 0;
    const size_t sig_size = rs_signature_size(scheme);

    t0 = hdkem_now_ns();
    if (mlkem768_keypair(pkS1, skS1) || x25519_keypair(pkS2, skS2)) return -1;
    S->keygen[i] = hdkem_now_ns() - t0;

    hdkem_writer_t w = { frame, sizeof frame, 0 };
    if (hdkem_put_bytes(&w, pkS1, sizeof pkS1) ||
        hdkem_put_bytes(&w, pkS2, sizeof pkS2) ||
        hdkem_put_lv16(&w, ID_S, ID_S_LEN) ||
        hdkem_put_u8(&w, (uint8_t)mode)) return -1;
    if (mode == HDKEM_MODE_SOURCELESS) {
        uint8_t auth[MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE + HDKEM_MAX_ID + 8];
        uint8_t sigS[HDKEM_MAX_SIGNATURE_SIZE];
        size_t alen = hdkem_build_hello_auth(auth, sizeof auth, pkS1, pkS2,
                                             ID_S, ID_S_LEN, mode);
        if (!alen || rs_sign(scheme, rskS, auth, alen, &ring->as_server, sigS) ||
            hdkem_put_bytes(&w, sigS, sig_size)) return -1;
    }
    if (hdkem_send_frame(fd, frame, w.off)) return -1;
    wire += w.off;

    ssize_t nr = hdkem_recv_frame(fd, frame, sizeof frame);
    if (nr <= 0) return -1;
    wire += (size_t)nr;
    hdkem_reader_t r = { frame, (size_t)nr, 0 };
    uint8_t c[MLKEM_CIPHERTEXT_SIZE], pkC2[X25519_PUBLIC_KEY_SIZE];
    uint8_t idC[HDKEM_MAX_ID], kid3[HDKEM_SOURCE_ID_BYTES];
    size_t idC_len = 0, kid3_len = 0;
    if (hdkem_get_bytes(&r, c, sizeof c) ||
        hdkem_get_bytes(&r, pkC2, sizeof pkC2) ||
        hdkem_get_lv16(&r, idC, sizeof idC, &idC_len) ||
        hdkem_get_lv16(&r, kid3, sizeof kid3, &kid3_len)) return -1;
    if (idC_len != ID_C_LEN || memcmp(idC, ID_C, ID_C_LEN)) return -1;
    if ((hdkem_mode_has_source(mode) && kid3_len != HDKEM_SOURCE_ID_BYTES) ||
        (!hdkem_mode_has_source(mode) && kid3_len != 0)) return -1;

    size_t tau_len = hdkem_build_tau(tau, sizeof tau, pkS1, c, pkC2, pkS2,
                                     idC, idC_len, ID_S, ID_S_LEN, mode,
                                     kid3_len ? kid3 : NULL, kid3_len);
    if (!tau_len) return -1;

    uint8_t sigma[HDKEM_MAX_SIGNATURE_SIZE];
    if (mode != HDKEM_MODE_HIDE) {
        if ((size_t)nr - r.off != sig_size) return -1;
        memcpy(sigma, frame + r.off, sig_size); r.off += sig_size;
        t0 = hdkem_now_ns();
        if (rs_verify(scheme, tau, tau_len, sigma, &ring->as_client)) return -1;
        S->verify[i] = hdkem_now_ns() - t0;
    }

    t0 = hdkem_now_ns();
    if (mlkem768_decapsulate(skS1, c, k1)) return -1;
    S->decaps[i] = hdkem_now_ns() - t0;
    t0 = hdkem_now_ns();
    if (x25519_shared_secret(skS2, pkC2, k2)) return -1;
    S->dh[i] = hdkem_now_ns() - t0;

    size_t k3_len = 0;
    if (hdkem_mode_has_source(mode)) {
        t0 = hdkem_now_ns();
        if (hdkem_source_derive(source_master, kid3, k3, source_bytes)) return -1;
        S->source[i] = hdkem_now_ns() - t0;
        k3_len = source_bytes;
    }

    size_t okm_len = mode == HDKEM_MODE_HIDE ? 96u : 64u;
    t0 = hdkem_now_ns();
    if (hdkem_skprf(k1, sizeof k1, k2, sizeof k2,
                    k3_len ? k3 : NULL, k3_len, tau, tau_len, okm, okm_len)) return -1;
    S->skprf[i] = hdkem_now_ns() - t0;
    const uint8_t *kcf = okm + 32, *kenc = okm + 64;

    if (mode == HDKEM_MODE_HIDE) {
        size_t need = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES + sig_size;
        if ((size_t)nr - r.off != need) return -1;
        const uint8_t *nu = frame + r.off; r.off += HDKEM_AEAD_NONCE_BYTES;
        const uint8_t *tag = frame + r.off; r.off += HDKEM_AEAD_TAG_BYTES;
        uint8_t enc_key[HDKEM_AEAD_KEY_BYTES];
        hdkem_ascon_key(enc_key, kenc);
        int dec_rc = ascon_decrypt(enc_key, nu, frame + r.off,
                                   sig_size,
                                   NULL, 0, tag, sigma);
        sodium_memzero(enc_key, sizeof enc_key);
        if (dec_rc) return -1;
        r.off += sig_size;
        t0 = hdkem_now_ns();
        if (rs_verify(scheme, tau, tau_len, sigma, &ring->as_client)) return -1;
        S->verify[i] = hdkem_now_ns() - t0;
    }
    if (r.off != (size_t)nr) return -1;

    size_t fin_len;
    t0 = hdkem_now_ns();
    if (build_finished(frame, sizeof frame, &fin_len, kcf, LABEL_S, tau, tau_len)) return -1;
    if (hdkem_send_frame(fd, frame, fin_len)) return -1;
    wire += fin_len;

    nr = hdkem_recv_frame(fd, frame, sizeof frame);
    if (nr <= 0) return -1;
    wire += (size_t)nr;
    if (verify_finished(frame, (size_t)nr, kcf, LABEL_C, tau, tau_len)) return -1;
    S->aead[i] = hdkem_now_ns() - t0;

    S->total[i] = hdkem_now_ns() - all0;
    *payload_wire = wire;
    sodium_memzero(skS1, sizeof skS1); sodium_memzero(skS2, sizeof skS2);
    sodium_memzero(k1, sizeof k1); sodium_memzero(k2, sizeof k2);
    sodium_memzero(k3, sizeof k3); sodium_memzero(okm, sizeof okm);
    sodium_memzero(sigma, sizeof sigma);
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr, "usage: %s --gen | --source-gen | [-p port] [-n reps] [-m src|sourceless|hide] [-b 32|48] [-r gandalf|falconrs]\n", p);
}

int main(int argc, char **argv)
{
    int port = 8443; size_t reps = 100, source_bytes = 48;
    hdkem_mode_t mode = HDKEM_MODE_SRC;
    rs_scheme_t scheme = RS_SCHEME_GANDALF;
    /* Pre-scan for -r so it applies to --gen / --source-gen regardless of
     * where on the command line it appears (--gen returns immediately when
     * matched below, so a -r appearing after it in argv would otherwise
     * never be seen). */
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "-r")) {
            if (rs_scheme_from_name(argv[i+1], &scheme)) { usage(argv[0]); return 1; }
            break;
        }
    }
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i], "--gen")) {
            if (sodium_init() < 0) return 1;
            uint8_t pk[HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
            uint8_t sk[HDKEM_MAX_RS_SECRET_KEY_SIZE];
            if (rs_keypair(scheme, pk, sk) ||
                hdkem_write_file(SRV_RVK, pk, rs_public_key_size(scheme)) ||
                hdkem_write_file(SRV_RSK, sk, rs_secret_key_size(scheme))) return 1;
            printf("wrote %s and %s (scheme=%s)\n", SRV_RVK, SRV_RSK, rs_scheme_name(scheme)); return 0;
        } else if (!strcmp(argv[i], "--source-gen")) {
            if (sodium_init() < 0 || hdkem_generate_source_master(HDKEM_SOURCE_FILE)) return 1;
            printf("wrote %s (%u B); copy the same file to the peer\n", HDKEM_SOURCE_FILE, HDKEM_SOURCE_MASTER_BYTES); return 0;
        } else if (!strcmp(argv[i], "-p") && i+1<argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i+1<argc) reps = strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i], "-b") && i+1<argc) source_bytes = strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i], "-r") && i+1<argc) {
            if (rs_scheme_from_name(argv[++i], &scheme)) { usage(argv[0]); return 1; }
        } else if (!strcmp(argv[i], "-m") && i+1<argc) {
            const char *m=argv[++i];
            if (!strcmp(m,"src")) mode=HDKEM_MODE_SRC;
            else if (!strcmp(m,"sourceless")) mode=HDKEM_MODE_SOURCELESS;
            else if (!strcmp(m,"hide")) mode=HDKEM_MODE_HIDE;
            else { usage(argv[0]); return 1; }
        } else { usage(argv[0]); return 1; }
    }
    if (source_bytes != 32u && source_bytes != 48u) return 1;
    if (sodium_init() < 0) return 1;

    uint8_t rskS[HDKEM_MAX_RS_SECRET_KEY_SIZE], rvkS[HDKEM_MAX_RS_PUBLIC_KEY_SIZE], rvkC[HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
    if (hdkem_read_file(SRV_RSK, rskS, rs_secret_key_size(scheme)) ||
        hdkem_read_file(SRV_RVK, rvkS, rs_public_key_size(scheme)) ||
        hdkem_read_file(CLI_RVK, rvkC, rs_public_key_size(scheme))) {
        fprintf(stderr, "missing ring keys; run --gen at both endpoints and exchange *.rvk out of band\n"); return 1;
    }
    uint8_t source_master[HDKEM_SOURCE_MASTER_BYTES] = {0};
    if (hdkem_mode_has_source(mode) && hdkem_read_file(HDKEM_SOURCE_FILE, source_master, sizeof source_master)) {
        fprintf(stderr, "missing %s\n", HDKEM_SOURCE_FILE); return 1;
    }
    hdkem_ring_t ring; hdkem_ring_init(&ring, rvkS, rvkC, scheme);

    srv_samples_t S={0}; S.n=reps;
#define ALLOC(name) do { S.name=calloc(reps,sizeof(uint64_t)); if(!S.name) return 1; } while(0)
    ALLOC(keygen); ALLOC(verify); ALLOC(decaps); ALLOC(dh); ALLOC(source); ALLOC(skprf); ALLOC(aead); ALLOC(total);
#undef ALLOC

    hdkem_wire_account_t expected=hdkem_expected_wire(ID_C_LEN,ID_S_LEN,mode,strlen(LABEL_S),strlen(LABEL_C),scheme);
    printf("HDKEM server v%u mode=%s scheme=%s source=%zuB reps=%zu port=%d\n",
           HDKEM_ARTIFACT_VERSION,hdkem_mode_name(mode),rs_scheme_name(scheme),source_bytes,reps,port);
    hdkem_print_wire_account(&expected);

    int ss=socket(AF_INET,SOCK_STREAM,0); if(ss<0) return 1;
    int one=1; setsockopt(ss,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=INADDR_ANY; a.sin_port=htons((uint16_t)port);
    if(bind(ss,(struct sockaddr*)&a,sizeof a)||listen(ss,16)){perror("server");return 1;}

    size_t done=0,last_wire=0,fail=0;
    while(done<reps && fail<20){
        int cs=accept(ss,NULL,NULL); if(cs<0) continue;
        setsockopt(cs,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one);
        size_t w=0;
        if(!serve_one(cs,&ring,rskS,source_master,mode,source_bytes,scheme,&S,done,&w)){last_wire=w;done++;fail=0;} else fail++;
        close(cs);
    }
    close(ss); if(!done) return 1;

    printf("\nServer results (%zu successful)\n",done);
    hdkem_report("ephemeral keygen",S.keygen,done);
    { char lbl[32]; snprintf(lbl,sizeof lbl,"%s verify",rs_scheme_name(scheme));
      hdkem_report(lbl,S.verify,done); }
    hdkem_report("ML-KEM decaps",S.decaps,done);
    hdkem_report("X25519 DH",S.dh,done);
    if(hdkem_mode_has_source(mode)) hdkem_report("Src.GetWithID",S.source,done);
    hdkem_report("split-key PRF",S.skprf,done);
    hdkem_report("Finished AEAD",S.aead,done);
    hdkem_report("server total incl I/O",S.total,done);
    printf("  measured protocol payload     %zu B\n",last_wire);
    printf("  measured TCP app bytes        %zu B\n",last_wire+4u*HDKEM_FRAME_HEADER_BYTES);
    if(last_wire!=expected.total_payload){
        fprintf(stderr,"FATAL accounting mismatch: measured=%zu expected=%zu\n",last_wire,expected.total_payload); return 2;
    }

    sodium_memzero(source_master,sizeof source_master); sodium_memzero(rskS,sizeof rskS);
    free(S.keygen);free(S.verify);free(S.decaps);free(S.dh);free(S.source);free(S.skprf);free(S.aead);free(S.total);
    return 0;
}
