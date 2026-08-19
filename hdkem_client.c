#include "hdkem_wire.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define CLI_RSK "client.rsk"
#define CLI_RVK "client.rvk"
#define SRV_RVK "server.rvk"

static const uint8_t ID_S[] = "SubstationServer001";
static const uint8_t ID_C[] = "SmartMeterClient042";
#define ID_S_LEN (sizeof ID_S - 1u)
#define ID_C_LEN (sizeof ID_C - 1u)

static const char LABEL_S[] = "HDKEM-v1-server-finished";
static const char LABEL_C[] = "HDKEM-v1-client-finished";

typedef struct {
    uint64_t *keygen, *encaps, *dh, *source, *skprf, *sign, *aead, *total;
    size_t n;
} cli_samples_t;

static int connect_to(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static int parse_hello(const uint8_t *frame, size_t n, hdkem_mode_t expected,
                       const hdkem_ring_t *ring, rs_scheme_t scheme,
                       uint8_t pkS1[MLKEM_PUBLIC_KEY_SIZE],
                       uint8_t pkS2[X25519_PUBLIC_KEY_SIZE],
                       uint8_t idS[HDKEM_MAX_ID], size_t *idS_len)
{
    hdkem_reader_t r = { frame, n, 0 };
    uint8_t mode8;
    if (hdkem_get_bytes(&r, pkS1, MLKEM_PUBLIC_KEY_SIZE) ||
        hdkem_get_bytes(&r, pkS2, X25519_PUBLIC_KEY_SIZE) ||
        hdkem_get_lv16(&r, idS, HDKEM_MAX_ID, idS_len) ||
        hdkem_get_u8(&r, &mode8)) return -1;
    if ((hdkem_mode_t)mode8 != expected) return -1;

    if (expected == HDKEM_MODE_SOURCELESS) {
        const size_t sig_size = rs_signature_size(scheme);
        if (n - r.off != sig_size) return -1;
        uint8_t auth[MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE + HDKEM_MAX_ID + 8];
        size_t alen = hdkem_build_hello_auth(auth, sizeof auth, pkS1, pkS2,
                                             idS, *idS_len, expected);
        if (!alen || rs_verify(scheme, auth, alen, frame + r.off, &ring->as_server)) return -1;
        r.off += sig_size;
    }
    return r.off == n ? 0 : -1;
}

static int verify_finished(const uint8_t *frame, size_t n,
                           const uint8_t *kcf,
                           const char *label,
                           const uint8_t *tau, size_t tau_len)
{
    const size_t fixed = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES;
    if (n < fixed) return -1;
    const uint8_t *nu = frame;
    const uint8_t *tag = frame + HDKEM_AEAD_NONCE_BYTES;
    const uint8_t *ct = frame + fixed;
    size_t ct_len = n - fixed;
    size_t lab = strlen(label);
    if (ct_len != lab + tau_len) return -1;
    uint8_t *pt = malloc(ct_len ? ct_len : 1);
    if (!pt) return -1;
    uint8_t aead_key[HDKEM_AEAD_KEY_BYTES];
    hdkem_ascon_key(aead_key, kcf);
    int rc = ascon_decrypt(aead_key, nu, ct, ct_len, NULL, 0, tag, pt);
    sodium_memzero(aead_key, sizeof aead_key);
    if (!rc && (memcmp(pt, label, lab) || memcmp(pt + lab, tau, tau_len))) rc = -1;
    sodium_memzero(pt, ct_len);
    free(pt);
    return rc;
}

static int build_finished(uint8_t *frame, size_t cap, size_t *out_len,
                          const uint8_t *kcf, const char *label,
                          const uint8_t *tau, size_t tau_len)
{
    size_t lab = strlen(label), pt_len = lab + tau_len;
    if (HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES + pt_len > cap) return -1;
    uint8_t *pt = malloc(pt_len ? pt_len : 1);
    if (!pt) return -1;
    memcpy(pt, label, lab);
    memcpy(pt + lab, tau, tau_len);
    uint8_t *nu = frame;
    uint8_t *tag = frame + HDKEM_AEAD_NONCE_BYTES;
    uint8_t *ct = frame + HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES;
    randombytes_buf(nu, HDKEM_AEAD_NONCE_BYTES);
    uint8_t aead_key[HDKEM_AEAD_KEY_BYTES];
    hdkem_ascon_key(aead_key, kcf);
    int rc = ascon_encrypt(aead_key, nu, pt, pt_len, NULL, 0, ct, tag);
    sodium_memzero(aead_key, sizeof aead_key);
    sodium_memzero(pt, pt_len);
    free(pt);
    if (rc) return -1;
    *out_len = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES + pt_len;
    return 0;
}

static int run_one(int fd, const hdkem_ring_t *ring, const uint8_t *rskC,
                   const uint8_t source_master[HDKEM_SOURCE_MASTER_BYTES],
                   hdkem_mode_t mode, size_t source_bytes, rs_scheme_t scheme,
                   cli_samples_t *C, size_t i, size_t *payload_wire)
{
    uint8_t frame[HDKEM_MAX_FRAME], tau[HDKEM_MAX_TAU];
    uint8_t k1[32], k2[32], k3[HDKEM_SOURCE_MAX_BYTES], okm[96];
    uint8_t kid3[HDKEM_SOURCE_ID_BYTES];
    size_t kid3_len = 0, k3_len = 0, wire = 0;
    const size_t sig_size = rs_signature_size(scheme);
    uint64_t all0 = hdkem_now_ns(), t0;

    ssize_t nr = hdkem_recv_frame(fd, frame, sizeof frame);
    if (nr <= 0) return -1;
    wire += (size_t)nr;

    uint8_t pkS1[MLKEM_PUBLIC_KEY_SIZE], pkS2[X25519_PUBLIC_KEY_SIZE];
    uint8_t idS[HDKEM_MAX_ID]; size_t idS_len = 0;
    if (parse_hello(frame, (size_t)nr, mode, ring, scheme, pkS1, pkS2, idS, &idS_len)) return -1;
    if (idS_len != ID_S_LEN || memcmp(idS, ID_S, ID_S_LEN)) return -1;

    uint8_t pkC2[X25519_PUBLIC_KEY_SIZE], skC2[X25519_SECRET_KEY_SIZE];
    t0 = hdkem_now_ns();
    if (x25519_keypair(pkC2, skC2)) return -1;
    C->keygen[i] = hdkem_now_ns() - t0;

    uint8_t c[MLKEM_CIPHERTEXT_SIZE];
    t0 = hdkem_now_ns();
    if (mlkem768_encapsulate(pkS1, c, k1)) return -1;
    C->encaps[i] = hdkem_now_ns() - t0;

    t0 = hdkem_now_ns();
    if (x25519_shared_secret(skC2, pkS2, k2)) return -1;
    C->dh[i] = hdkem_now_ns() - t0;

    if (hdkem_mode_has_source(mode)) {
        t0 = hdkem_now_ns();
        if (hdkem_source_get(source_master, kid3, k3, source_bytes)) return -1;
        C->source[i] = hdkem_now_ns() - t0;
        kid3_len = HDKEM_SOURCE_ID_BYTES;
        k3_len = source_bytes;
    }

    size_t tau_len = hdkem_build_tau(tau, sizeof tau, pkS1, c, pkC2, pkS2,
                                     ID_C, ID_C_LEN, idS, idS_len, mode,
                                     kid3_len ? kid3 : NULL, kid3_len);
    if (!tau_len) return -1;

    size_t okm_len = mode == HDKEM_MODE_HIDE ? 96u : 64u;
    t0 = hdkem_now_ns();
    if (hdkem_skprf(k1, sizeof k1, k2, sizeof k2,
                    k3_len ? k3 : NULL, k3_len, tau, tau_len, okm, okm_len)) return -1;
    C->skprf[i] = hdkem_now_ns() - t0;
    const uint8_t *kcf = okm + 32;
    const uint8_t *kenc = okm + 64;

    uint8_t sigma[HDKEM_MAX_SIGNATURE_SIZE];
    t0 = hdkem_now_ns();
    if (rs_sign(scheme, rskC, tau, tau_len, &ring->as_client, sigma)) return -1;
    C->sign[i] = hdkem_now_ns() - t0;

    hdkem_writer_t w = { frame, sizeof frame, 0 };
    if (hdkem_put_bytes(&w, c, sizeof c) ||
        hdkem_put_bytes(&w, pkC2, sizeof pkC2) ||
        hdkem_put_lv16(&w, ID_C, ID_C_LEN) ||
        hdkem_put_lv16(&w, kid3_len ? kid3 : NULL, kid3_len)) return -1;

    if (mode == HDKEM_MODE_HIDE) {
        uint8_t nu[HDKEM_AEAD_NONCE_BYTES], tag[HDKEM_AEAD_TAG_BYTES];
        uint8_t sealed[HDKEM_MAX_SIGNATURE_SIZE];
        randombytes_buf(nu, sizeof nu);
        uint8_t enc_key[HDKEM_AEAD_KEY_BYTES];
        hdkem_ascon_key(enc_key, kenc);
        int enc_rc = ascon_encrypt(enc_key, nu, sigma, sig_size,
                                   NULL, 0, sealed, tag);
        sodium_memzero(enc_key, sizeof enc_key);
        if (enc_rc) return -1;
        if (hdkem_put_bytes(&w, nu, sizeof nu) ||
            hdkem_put_bytes(&w, tag, sizeof tag) ||
            hdkem_put_bytes(&w, sealed, sig_size)) return -1;
    } else if (hdkem_put_bytes(&w, sigma, sig_size)) return -1;

    if (hdkem_send_frame(fd, frame, w.off)) return -1;
    wire += w.off;

    nr = hdkem_recv_frame(fd, frame, sizeof frame);
    if (nr <= 0) return -1;
    wire += (size_t)nr;
    t0 = hdkem_now_ns();
    if (verify_finished(frame, (size_t)nr, kcf, LABEL_S, tau, tau_len)) return -1;

    size_t fin_len;
    if (build_finished(frame, sizeof frame, &fin_len, kcf, LABEL_C, tau, tau_len)) return -1;
    if (hdkem_send_frame(fd, frame, fin_len)) return -1;
    wire += fin_len;
    C->aead[i] = hdkem_now_ns() - t0;

    C->total[i] = hdkem_now_ns() - all0;
    *payload_wire = wire;

    sodium_memzero(skC2, sizeof skC2);
    sodium_memzero(k1, sizeof k1); sodium_memzero(k2, sizeof k2);
    sodium_memzero(k3, sizeof k3); sodium_memzero(okm, sizeof okm);
    sodium_memzero(sigma, sizeof sigma);
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s --gen | --source-gen | [-h host] [-p port] [-n reps] "
        "[-m src|sourceless|hide] [-b 32|48] [-r gandalf|falconrs] [-o csv]\n", p);
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *csv = NULL;
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

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--gen")) {
            if (sodium_init() < 0) return 1;
            uint8_t pk[HDKEM_MAX_RS_PUBLIC_KEY_SIZE], sk[HDKEM_MAX_RS_SECRET_KEY_SIZE];
            if (rs_keypair(scheme, pk, sk) ||
                hdkem_write_file(CLI_RVK, pk, rs_public_key_size(scheme)) ||
                hdkem_write_file(CLI_RSK, sk, rs_secret_key_size(scheme))) return 1;
            printf("wrote %s and %s (scheme=%s)\n", CLI_RVK, CLI_RSK, rs_scheme_name(scheme)); return 0;
        } else if (!strcmp(argv[i], "--source-gen")) {
            if (sodium_init() < 0 || hdkem_generate_source_master(HDKEM_SOURCE_FILE)) return 1;
            printf("wrote %s (%u B); copy the same file to the peer\n",
                   HDKEM_SOURCE_FILE, HDKEM_SOURCE_MASTER_BYTES); return 0;
        } else if (!strcmp(argv[i], "-h") && i+1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "-p") && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i+1 < argc) reps = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-b") && i+1 < argc) source_bytes = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-o") && i+1 < argc) csv = argv[++i];
        else if (!strcmp(argv[i], "-r") && i+1 < argc) {
            if (rs_scheme_from_name(argv[++i], &scheme)) { usage(argv[0]); return 1; }
        } else if (!strcmp(argv[i], "-m") && i+1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "src")) mode = HDKEM_MODE_SRC;
            else if (!strcmp(m, "sourceless")) mode = HDKEM_MODE_SOURCELESS;
            else if (!strcmp(m, "hide")) mode = HDKEM_MODE_HIDE;
            else { usage(argv[0]); return 1; }
        } else { usage(argv[0]); return 1; }
    }
    if (source_bytes != 32u && source_bytes != 48u) { fprintf(stderr, "-b must be 32 or 48\n"); return 1; }
    if (sodium_init() < 0) return 1;

    uint8_t rskC[HDKEM_MAX_RS_SECRET_KEY_SIZE], rvkC[HDKEM_MAX_RS_PUBLIC_KEY_SIZE], rvkS[HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
    if (hdkem_read_file(CLI_RSK, rskC, rs_secret_key_size(scheme)) ||
        hdkem_read_file(CLI_RVK, rvkC, rs_public_key_size(scheme)) ||
        hdkem_read_file(SRV_RVK, rvkS, rs_public_key_size(scheme))) {
        fprintf(stderr, "missing ring keys; run --gen at both endpoints and exchange *.rvk out of band\n");
        return 1;
    }
    uint8_t source_master[HDKEM_SOURCE_MASTER_BYTES] = {0};
    if (hdkem_mode_has_source(mode) &&
        hdkem_read_file(HDKEM_SOURCE_FILE, source_master, sizeof source_master)) {
        fprintf(stderr, "missing %s; run --source-gen once and provision the same file to both peers\n", HDKEM_SOURCE_FILE);
        return 1;
    }

    hdkem_ring_t ring; hdkem_ring_init(&ring, rvkS, rvkC, scheme);
    cli_samples_t C = {0}; C.n = reps;
#define ALLOC(name) do { C.name = calloc(reps, sizeof(uint64_t)); if (!C.name) return 1; } while (0)
    ALLOC(keygen); ALLOC(encaps); ALLOC(dh); ALLOC(source); ALLOC(skprf); ALLOC(sign); ALLOC(aead); ALLOC(total);
#undef ALLOC

    hdkem_wire_account_t expected = hdkem_expected_wire(ID_C_LEN, ID_S_LEN, mode,
                                                         strlen(LABEL_S), strlen(LABEL_C), scheme);
    printf("HDKEM client v%u mode=%s scheme=%s source=%zuB reps=%zu -> %s:%d\n",
           HDKEM_ARTIFACT_VERSION, hdkem_mode_name(mode), rs_scheme_name(scheme), source_bytes, reps, host, port);
    hdkem_print_wire_account(&expected);

    size_t done = 0, fails = 0, last_wire = 0;
    while (done < reps && fails < reps + 20) {
        int fd = connect_to(host, port);
        if (fd < 0) { ++fails; usleep(20000); continue; }
        size_t w = 0;
        if (!run_one(fd, &ring, rskC, source_master, mode, source_bytes, scheme, &C, done, &w)) {
            last_wire = w; ++done;
        } else ++fails;
        close(fd);
    }
    if (!done) return 1;

    printf("\nClient results (%zu successful)\n", done);
    hdkem_report("X25519 keygen", C.keygen, done);
    hdkem_report("ML-KEM encaps", C.encaps, done);
    hdkem_report("X25519 DH", C.dh, done);
    if (hdkem_mode_has_source(mode)) hdkem_report("Src.Get", C.source, done);
    hdkem_report("split-key PRF", C.skprf, done);
    { char lbl[32]; snprintf(lbl,sizeof lbl,"%s sign",rs_scheme_name(scheme));
      hdkem_report(lbl, C.sign, done); }
    hdkem_report("Finished AEAD", C.aead, done);
    hdkem_report("client total incl I/O", C.total, done);
    printf("  measured protocol payload     %zu B\n", last_wire);
    printf("  measured TCP app bytes        %zu B\n", last_wire + 4u*HDKEM_FRAME_HEADER_BYTES);
    if (last_wire != expected.total_payload) {
        fprintf(stderr, "FATAL accounting mismatch: measured=%zu expected=%zu\n",
                last_wire, expected.total_payload); return 2;
    }

    if (csv) {
        FILE *f = fopen(csv, "w");
        if (!f) return 1;
        fprintf(f, "rep,keygen_ns,encaps_ns,dh_ns,source_ns,skprf_ns,sign_ns,aead_ns,total_ns,payload_bytes,tcp_app_bytes\n");
        for (size_t j = 0; j < done; ++j) {
            fprintf(f, "%zu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%zu,%zu\n",
                    j,
                    (unsigned long long)C.keygen[j],
                    (unsigned long long)C.encaps[j],
                    (unsigned long long)C.dh[j],
                    (unsigned long long)C.source[j],
                    (unsigned long long)C.skprf[j],
                    (unsigned long long)C.sign[j],
                    (unsigned long long)C.aead[j],
                    (unsigned long long)C.total[j],
                    last_wire, last_wire + 4u * HDKEM_FRAME_HEADER_BYTES);
        }
        fclose(f);
    }

    sodium_memzero(source_master, sizeof source_master);
    sodium_memzero(rskC, sizeof rskC);
    free(C.keygen); free(C.encaps); free(C.dh); free(C.source);
    free(C.skprf); free(C.sign); free(C.aead); free(C.total);
    return 0;
}
