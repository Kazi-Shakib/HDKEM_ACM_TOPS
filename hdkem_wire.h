#ifndef HDKEM_WIRE_H
#define HDKEM_WIRE_H

#include "hdkem_primitives.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <sodium.h>

/* Protocol version implemented by this artifact. */
#define HDKEM_ARTIFACT_VERSION 8u

#define HDKEM_AEAD_KEY_BYTES    ASCON_KEY_SIZE
#define HDKEM_AEAD_NONCE_BYTES  ASCON_NONCE_SIZE
#define HDKEM_AEAD_TAG_BYTES    ASCON_TAG_SIZE
#define HDKEM_KSH_BYTES          32u
#define HDKEM_KCF_BYTES          32u
#define HDKEM_KENC_BYTES         32u
#define HDKEM_SOURCE_ID_BYTES    16u
#define HDKEM_SOURCE_MASTER_BYTES 48u
#define HDKEM_SOURCE_MAX_BYTES   48u
#define HDKEM_MAX_ID             64u
#define HDKEM_MAX_TAU            4096u
#define HDKEM_MAX_FRAME          16384u
#define HDKEM_FRAME_HEADER_BYTES 4u

#define HDKEM_SOURCE_FILE "source_master.bin"
#define HDKEM_SKPRF_DST   "HDKEM-v1-skPRF"
#define HDKEM_SOURCE_DST  "HDKEM-v1-source-derive"

/*
 * k_cf and k_enc are 256-bit logical split-key-PRF outputs. Ascon-128a
 * consumes a 128-bit key, instantiated here as the first 16 bytes.
 * Keeping the conversion explicit avoids relying on implicit pointer
 * truncation at the AEAD call sites.
 */
static inline void hdkem_ascon_key(uint8_t out[HDKEM_AEAD_KEY_BYTES],
                                   const uint8_t logical_key[32])
{
    memcpy(out, logical_key, HDKEM_AEAD_KEY_BYTES);
}

typedef enum {
    HDKEM_MODE_SRC        = 0,
    HDKEM_MODE_SOURCELESS = 1,
    HDKEM_MODE_HIDE       = 2
} hdkem_mode_t;

static inline const char *hdkem_mode_name(hdkem_mode_t m)
{
    switch (m) {
    case HDKEM_MODE_SRC: return "src";
    case HDKEM_MODE_SOURCELESS: return "sourceless";
    case HDKEM_MODE_HIDE: return "hide";
    default: return "invalid";
    }
}

static inline int hdkem_mode_has_source(hdkem_mode_t m)
{
    return m == HDKEM_MODE_SRC || m == HDKEM_MODE_HIDE;
}

/* ---------- bounded cursor helpers ---------- */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t off;
} hdkem_writer_t;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;
} hdkem_reader_t;

static inline int hdkem_put_bytes(hdkem_writer_t *w, const void *src, size_t n)
{
    if (!w || n > w->cap - w->off) return -1;
    if (n) memcpy(w->buf + w->off, src, n);
    w->off += n;
    return 0;
}

static inline int hdkem_put_u8(hdkem_writer_t *w, uint8_t x)
{
    return hdkem_put_bytes(w, &x, 1);
}

static inline int hdkem_put_u16(hdkem_writer_t *w, size_t x)
{
    if (x > 0xffffu) return -1;
    uint8_t b[2] = { (uint8_t)(x >> 8), (uint8_t)x };
    return hdkem_put_bytes(w, b, 2);
}

static inline int hdkem_put_lv16(hdkem_writer_t *w, const uint8_t *x, size_t n)
{
    return hdkem_put_u16(w, n) || hdkem_put_bytes(w, x, n) ? -1 : 0;
}

static inline int hdkem_get_bytes(hdkem_reader_t *r, void *dst, size_t n)
{
    if (!r || n > r->len - r->off) return -1;
    if (n) memcpy(dst, r->buf + r->off, n);
    r->off += n;
    return 0;
}

static inline int hdkem_get_u8(hdkem_reader_t *r, uint8_t *x)
{
    return hdkem_get_bytes(r, x, 1);
}

static inline int hdkem_get_u16(hdkem_reader_t *r, size_t *x)
{
    uint8_t b[2];
    if (hdkem_get_bytes(r, b, 2)) return -1;
    *x = ((size_t)b[0] << 8) | b[1];
    return 0;
}

static inline int hdkem_get_lv16(hdkem_reader_t *r, uint8_t *dst,
                                 size_t cap, size_t *out_len)
{
    size_t n;
    if (hdkem_get_u16(r, &n) || n > cap) return -1;
    if (hdkem_get_bytes(r, dst, n)) return -1;
    *out_len = n;
    return 0;
}

/* ---------- split-key PRF and source derivation ---------- */
static inline int hdkem_xof_lv(EVP_MD_CTX *ctx, const uint8_t *x, size_t n)
{
    if (n > 0xffffu) return -1;
    uint8_t len2[2] = { (uint8_t)(n >> 8), (uint8_t)n };
    if (EVP_DigestUpdate(ctx, len2, sizeof len2) != 1) return -1;
    if (n && EVP_DigestUpdate(ctx, x, n) != 1) return -1;
    return 0;
}

static inline int hdkem_skprf(const uint8_t *k1, size_t k1_len,
                              const uint8_t *k2, size_t k2_len,
                              const uint8_t *k3, size_t k3_len,
                              const uint8_t *tau, size_t tau_len,
                              uint8_t *out, size_t out_len)
{
    if (!k1 || !k2 || !tau || !out || (k3_len && !k3)) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, HDKEM_SKPRF_DST, strlen(HDKEM_SKPRF_DST)) == 1 &&
             hdkem_xof_lv(ctx, k1, k1_len) == 0 &&
             hdkem_xof_lv(ctx, k2, k2_len) == 0 &&
             hdkem_xof_lv(ctx, k3, k3_len) == 0 &&
             hdkem_xof_lv(ctx, tau, tau_len) == 0 &&
             EVP_DigestFinalXOF(ctx, out, out_len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

/* PSK-backed emulator of Src.Get/Src.GetWithID for artifact testing.
 * A physical QKD service replaces these calls but preserves (kid3,k3).
 */
static inline int hdkem_source_derive(const uint8_t master[HDKEM_SOURCE_MASTER_BYTES],
                                      const uint8_t kid[HDKEM_SOURCE_ID_BYTES],
                                      uint8_t *k3, size_t k3_len)
{
    if (!master || !kid || !k3 || (k3_len != 32u && k3_len != 48u)) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, HDKEM_SOURCE_DST, strlen(HDKEM_SOURCE_DST)) == 1 &&
             hdkem_xof_lv(ctx, master, HDKEM_SOURCE_MASTER_BYTES) == 0 &&
             hdkem_xof_lv(ctx, kid, HDKEM_SOURCE_ID_BYTES) == 0 &&
             EVP_DigestFinalXOF(ctx, k3, k3_len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static inline int hdkem_source_get(const uint8_t master[HDKEM_SOURCE_MASTER_BYTES],
                                   uint8_t kid[HDKEM_SOURCE_ID_BYTES],
                                   uint8_t *k3, size_t k3_len)
{
    if (random_bytes(kid, HDKEM_SOURCE_ID_BYTES)) return -1;
    return hdkem_source_derive(master, kid, k3, k3_len);
}

/* ---------- transcript ----------
 * tau = pkS1 || c || pkC2 || pkS2 || <IDC> || <IDS> || mode || <kid3>
 * kid3 is public/authenticated. The secret k3 NEVER appears in tau.
 */
static inline size_t hdkem_build_tau(uint8_t *tau, size_t cap,
                                     const uint8_t *pkS1, const uint8_t *c,
                                     const uint8_t *pkC2, const uint8_t *pkS2,
                                     const uint8_t *idC, size_t idC_len,
                                     const uint8_t *idS, size_t idS_len,
                                     hdkem_mode_t mode,
                                     const uint8_t *kid3, size_t kid3_len)
{
    if (!tau || !pkS1 || !c || !pkC2 || !pkS2 || !idC || !idS) return 0;
    if (idC_len > HDKEM_MAX_ID || idS_len > HDKEM_MAX_ID) return 0;
    if (hdkem_mode_has_source(mode)) {
        if (!kid3 || kid3_len != HDKEM_SOURCE_ID_BYTES) return 0;
    } else if (kid3_len != 0) {
        return 0;
    }
    hdkem_writer_t w = { tau, cap, 0 };
    if (hdkem_put_bytes(&w, pkS1, MLKEM_PUBLIC_KEY_SIZE) ||
        hdkem_put_bytes(&w, c, MLKEM_CIPHERTEXT_SIZE) ||
        hdkem_put_bytes(&w, pkC2, X25519_PUBLIC_KEY_SIZE) ||
        hdkem_put_bytes(&w, pkS2, X25519_PUBLIC_KEY_SIZE) ||
        hdkem_put_lv16(&w, idC, idC_len) ||
        hdkem_put_lv16(&w, idS, idS_len) ||
        hdkem_put_u8(&w, (uint8_t)mode) ||
        hdkem_put_lv16(&w, kid3, kid3_len)) return 0;
    return w.off;
}

/* Source-less Hello signature input uses exactly the serialized public fields. */
static inline size_t hdkem_build_hello_auth(uint8_t *out, size_t cap,
                                            const uint8_t *pkS1,
                                            const uint8_t *pkS2,
                                            const uint8_t *idS, size_t idS_len,
                                            hdkem_mode_t mode)
{
    hdkem_writer_t w = { out, cap, 0 };
    if (hdkem_put_bytes(&w, pkS1, MLKEM_PUBLIC_KEY_SIZE) ||
        hdkem_put_bytes(&w, pkS2, X25519_PUBLIC_KEY_SIZE) ||
        hdkem_put_lv16(&w, idS, idS_len) ||
        hdkem_put_u8(&w, (uint8_t)mode)) return 0;
    return w.off;
}

/* ---------- ring ----------
 * Gandalf and FalconRS now have different public-key sizes (896 vs 897
 * bytes) since the Gandalf header correction, so the ring can no longer
 * assume one shared stride for both schemes. Pack at rs_public_key_size()
 * for whichever scheme is actually in use; size the backing buffer for
 * the larger of the two (HDKEM_MAX_RS_PUBLIC_KEY_SIZE) so either fits. */
typedef struct {
    uint8_t keys[2u * HDKEM_MAX_RS_PUBLIC_KEY_SIZE];
    gandalf_ring_t as_server;
    gandalf_ring_t as_client;
} hdkem_ring_t;

static inline void hdkem_ring_init(hdkem_ring_t *r,
                                   const uint8_t *rvkS,
                                   const uint8_t *rvkC,
                                   rs_scheme_t scheme)
{
    const size_t stride = rs_public_key_size(scheme);
    memcpy(r->keys, rvkS, stride);
    memcpy(r->keys + stride, rvkC, stride);
    r->as_server = (gandalf_ring_t){ r->keys, 2, 0 };
    r->as_client = (gandalf_ring_t){ r->keys, 2, 1 };
}

/* ---------- exact wire accounting ---------- */
typedef struct {
    size_t hello_payload;
    size_t client_auth_payload;
    size_t server_finished_payload;
    size_t client_finished_payload;
    size_t frame_headers;
    size_t total_payload;
    size_t total_tcp_bytes;
} hdkem_wire_account_t;

static inline size_t hdkem_tau_size(size_t idC_len, size_t idS_len,
                                    hdkem_mode_t mode)
{
    size_t kid = hdkem_mode_has_source(mode) ? HDKEM_SOURCE_ID_BYTES : 0u;
    return MLKEM_PUBLIC_KEY_SIZE + MLKEM_CIPHERTEXT_SIZE +
           2u * X25519_PUBLIC_KEY_SIZE +
           2u + idC_len + 2u + idS_len + 1u + 2u + kid;
}

static inline hdkem_wire_account_t
hdkem_expected_wire(size_t idC_len, size_t idS_len, hdkem_mode_t mode,
                    size_t labelS_len, size_t labelC_len,
                    rs_scheme_t scheme)
{
    hdkem_wire_account_t a;
    const size_t kid = hdkem_mode_has_source(mode) ? HDKEM_SOURCE_ID_BYTES : 0u;
    const size_t tau = hdkem_tau_size(idC_len, idS_len, mode);
    const size_t sig_size = rs_signature_size(scheme);
    a.hello_payload = MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE +
                      2u + idS_len + 1u +
                      (mode == HDKEM_MODE_SOURCELESS ? sig_size : 0u);
    a.client_auth_payload = MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE +
                            2u + idC_len + 2u + kid +
                            sig_size +
                            (mode == HDKEM_MODE_HIDE ?
                             HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES : 0u);
    a.server_finished_payload = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES +
                                labelS_len + tau;
    a.client_finished_payload = HDKEM_AEAD_NONCE_BYTES + HDKEM_AEAD_TAG_BYTES +
                                labelC_len + tau;
    a.frame_headers = 4u * HDKEM_FRAME_HEADER_BYTES;
    a.total_payload = a.hello_payload + a.client_auth_payload +
                      a.server_finished_payload + a.client_finished_payload;
    a.total_tcp_bytes = a.total_payload + a.frame_headers;
    return a;
}

static inline void hdkem_print_wire_account(const hdkem_wire_account_t *a)
{
    printf("  wire hello payload            %zu B\n", a->hello_payload);
    printf("  wire client-auth payload      %zu B\n", a->client_auth_payload);
    printf("  wire server-Finished payload  %zu B\n", a->server_finished_payload);
    printf("  wire client-Finished payload  %zu B\n", a->client_finished_payload);
    printf("  wire protocol payload total   %zu B\n", a->total_payload);
    printf("  wire frame headers            %zu B\n", a->frame_headers);
    printf("  wire TCP application bytes    %zu B\n", a->total_tcp_bytes);
}

/* ---------- framing with robust short-write handling ---------- */
static inline int hdkem_send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static inline int hdkem_recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static inline int hdkem_send_frame(int fd, const uint8_t *buf, size_t len)
{
    if (len > 0xffffffffu) return -1;
    uint8_t h[4] = { (uint8_t)(len >> 24), (uint8_t)(len >> 16),
                     (uint8_t)(len >> 8), (uint8_t)len };
    return hdkem_send_all(fd, h, sizeof h) || hdkem_send_all(fd, buf, len) ? -1 : 0;
}

static inline ssize_t hdkem_recv_frame(int fd, uint8_t *buf, size_t cap)
{
    uint8_t h[4];
    if (hdkem_recv_all(fd, h, sizeof h)) return -1;
    size_t len = ((size_t)h[0] << 24) | ((size_t)h[1] << 16) |
                 ((size_t)h[2] << 8) | h[3];
    if (len > cap) return -1;
    if (hdkem_recv_all(fd, buf, len)) return -1;
    return (ssize_t)len;
}

/* ---------- timing/statistics ---------- */
static inline uint64_t hdkem_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline int hdkem_cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static inline void hdkem_report(const char *label, uint64_t *s, size_t n)
{
    if (!n) return;
    qsort(s, n, sizeof s[0], hdkem_cmp_u64);
    const size_t i05 = (size_t)(0.05 * (double)(n - 1));
    const size_t i95 = (size_t)(0.95 * (double)(n - 1));
    printf("  %-26s med %8.4f ms  p05 %8.4f  p95 %8.4f  n=%zu\n",
           label, s[n/2]/1e6, s[i05]/1e6, s[i95]/1e6, n);
}

/* ---------- files ---------- */
static inline int hdkem_write_file(const char *path, const uint8_t *b, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(b, 1, n, f);
    int e = ferror(f);
    fclose(f);
    return (!e && w == n) ? 0 : -1;
}

static inline int hdkem_read_file(const char *path, uint8_t *b, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t r = fread(b, 1, n, f);
    int extra = fgetc(f);
    fclose(f);
    return (r == n && extra == EOF) ? 0 : -1;
}

static inline int hdkem_generate_source_master(const char *path)
{
    uint8_t m[HDKEM_SOURCE_MASTER_BYTES];
    if (random_bytes(m, sizeof m)) return -1;
    int rc = hdkem_write_file(path, m, sizeof m);
    sodium_memzero(m, sizeof m);
    return rc;
}

#endif
