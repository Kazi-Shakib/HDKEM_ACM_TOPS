/*
 * HDKEM Implementation — CORRECTED
 *
 * Fixes applied vs uploaded version:
 *  1. hdkem_derive_session_key — split-key PRF replaces XOR combiner
 *     skPRF(k1,k2,k3;ctx) = HKDF(DST||len(k1)||k1||len(k2)||k2||len(k3)||k3,
 *                                  salt=0^32, info=len(ctx)||ctx)
 *     Giacon et al. (PKC 2018) proved XOR-combiner insecure.
 *  2. hdkem_server_create_hello — ring_size=2 {server,server} self-ring for
 *     the server hello; the deniable ring {client,server} is used in client hello.
 *  3. Removed all [DEBUG] printfs that read uninitialised memory.
 */

#include "hdkem.h"
#include "hdkem_primitives.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

/* ===== Internal: split-key PRF combiner =====
 *
 * Paper §3 par:dst (Eq. 1):
 *   skPRF(κ1,...,κn; ctx) = HKDF(DST || <κ1>...<κn> || <ctx>)
 *   where <x> = 2-byte-BE-len(x) || x  (§3 par:dst)
 *   DST = "HDKEM-v1-skPRF"
 *
 * For n=3 slots each 32 bytes:
 *   IKM = DST(14) + (2+32) + (2+32) + (2+32) = 14 + 102 = 116 bytes
 *   info = 2-byte-BE-len(ctx) || ctx
 *
 * salt = 0^32 per HKDF convention for pure PRF use.
 */
/*
 * _skprf: split-key PRF per paper §3 par:dst.
 *
 * skPRF(κ1,...,κn; ctx) = HKDF(DST || <κ1>...<κn> || <ctx>)
 *   <x> = 2-byte-BE-len(x) || x
 *   DST = "HDKEM-v1-skPRF"
 *
 * Supports n=3 (k1,k2,k3) or n=4 (k0,k1,k2,k3 with PSK slot k0).
 * Pass k0=NULL for the 3-slot mode (no PSK/QKD pre-shared key).
 * Paper §4 para PSK: ksh = skPRF(k0,k1,k2,k3; τ) — strictly stronger.
 */
static int _skprf(const uint8_t *k0,   /* optional PSK slot, NULL to omit */
                  const uint8_t *k1, const uint8_t *k2, const uint8_t *k3,
                  const uint8_t *ctx, size_t ctx_len,
                  uint8_t *out, size_t out_len)
{
    static const uint8_t DST[] = "HDKEM-v1-skPRF";

    /* IKM = DST || [<k0>] || <k1> || <k2> || <k3>
     * <ki> = 0x00 0x20 || ki  (34 bytes for a 32-byte key)
     * Max: 14 + 4*34 = 150 bytes */
    uint8_t ikm[150];
    size_t off = 0;
    memcpy(ikm + off, DST, 14);  off += 14;

    /* Optional PSK slot k0 */
    if (k0) {
        ikm[off++] = 0x00; ikm[off++] = 0x20;
        memcpy(ikm + off, k0, 32); off += 32;
    }

    /* Mandatory slots k1, k2, k3 */
    const uint8_t *slots[3] = {k1, k2, k3};
    for (int i = 0; i < 3; i++) {
        ikm[off++] = 0x00; ikm[off++] = 0x20;
        memcpy(ikm + off, slots[i], 32); off += 32;
    }

    /* info = <ctx> = 2-byte-BE-len(ctx) || ctx */
    if (ctx_len > 65535) ctx_len = 65535;
    size_t info_len = 2 + ctx_len;
    uint8_t *info = malloc(info_len);
    if (!info) return -1;
    info[0] = (uint8_t)(ctx_len >> 8);
    info[1] = (uint8_t)(ctx_len & 0xFF);
    if (ctx && ctx_len) memcpy(info + 2, ctx, ctx_len);

    uint8_t salt[32] = {0};
    int rc = hkdf(salt, 32, ikm, off, info, info_len, out, out_len);
    free(info);
    return rc;
}

/* ===== Server-Side Implementation ===== */

int hdkem_server_init(hdkem_server_keys_t *server_keys,
                      const uint8_t *id, size_t id_len)
{
    if (!server_keys || !id || id_len == 0 || id_len > MAX_ID_SIZE)
        return HDKEM_ERROR_INVALID_PARAM;

    if (mlkem768_keypair(server_keys->mlkem.public_key,
                         server_keys->mlkem.secret_key) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    if (x25519_keypair(server_keys->x25519.public_key,
                       server_keys->x25519.secret_key) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    if (gandalf_keypair(server_keys->gandalf.public_key,
                        server_keys->gandalf.secret_key) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    memcpy(server_keys->id, id, id_len);
    server_keys->id_len = id_len;
    return HDKEM_SUCCESS;
}

int hdkem_server_create_hello(const hdkem_server_keys_t *server_keys,
                               const uint8_t *client_gandalf_pk,
                               hdkem_server_hello_t *hello)
{
    if (!server_keys || !client_gandalf_pk || !hello) return HDKEM_ERROR_INVALID_PARAM;

    memcpy(hello->mlkem_public_key, server_keys->mlkem.public_key, MLKEM_PUBLIC_KEY_SIZE);
    memcpy(hello->x25519_public_key, server_keys->x25519.public_key, X25519_PUBLIC_KEY_SIZE);
    memcpy(hello->server_id, server_keys->id, server_keys->id_len);
    hello->server_id_len = server_keys->id_len;

    /* Paper §4: sig_s = RingSign(R, k_pr_s3, k_pub_s1 || k_pub_s2 || ID_S)
     * Ring R = {k_pub_s3, k_pub_r3} — both keys provisioned out-of-band. */
    uint8_t msg[MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE + MAX_ID_SIZE];
    size_t mlen = 0;
    memcpy(msg + mlen, hello->mlkem_public_key,  MLKEM_PUBLIC_KEY_SIZE);  mlen += MLKEM_PUBLIC_KEY_SIZE;
    memcpy(msg + mlen, hello->x25519_public_key, X25519_PUBLIC_KEY_SIZE); mlen += X25519_PUBLIC_KEY_SIZE;
    memcpy(msg + mlen, hello->server_id,          hello->server_id_len);   mlen += hello->server_id_len;

    /* R = {server_pk, client_pk} — canonical ring as per paper.
     * server is index 0 (signer), client is index 1. */
    uint8_t ring_keys[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(ring_keys,                          server_keys->gandalf.public_key, GANDALF_PUBLIC_KEY_SIZE);
    memcpy(ring_keys + GANDALF_PUBLIC_KEY_SIZE, client_gandalf_pk,              GANDALF_PUBLIC_KEY_SIZE);

    gandalf_ring_t ring = {
        .ring_public_keys = ring_keys,
        .ring_size        = 2,
        .signer_index     = 0
    };

    if (gandalf_sign(server_keys->gandalf.secret_key, msg, mlen, &ring,
                     hello->signature) != 0)
        return HDKEM_ERROR_SIGNATURE;

    return HDKEM_SUCCESS;
}

int hdkem_server_process_client_hello(const hdkem_server_keys_t *server_keys,
                                       const hdkem_client_hello_t *client_hello,
                                       const uint8_t *client_pk_gandalf,
                                       const uint8_t *k3_qkd,
                                       hdkem_session_t *session)
{
    if (!server_keys || !client_hello || !session ||
        !client_pk_gandalf || !k3_qkd)
        return HDKEM_ERROR_INVALID_PARAM;

    /* Message that was signed: c || k_pub_r2 || ID_S || ID_C || k3
     * Paper §4: sig_r covers c||k_pub_r2||ID_S||ID_C||k3 */
    uint8_t msg[MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE +
                MAX_ID_SIZE + MAX_ID_SIZE + QKD_KEY_SIZE];
    size_t mlen = 0;
    memcpy(msg + mlen, client_hello->mlkem_ciphertext,  MLKEM_CIPHERTEXT_SIZE);  mlen += MLKEM_CIPHERTEXT_SIZE;
    memcpy(msg + mlen, client_hello->x25519_public_key, X25519_PUBLIC_KEY_SIZE); mlen += X25519_PUBLIC_KEY_SIZE;
    memcpy(msg + mlen, server_keys->id,                 server_keys->id_len);    mlen += server_keys->id_len;
    memcpy(msg + mlen, client_hello->client_id,         client_hello->client_id_len); mlen += client_hello->client_id_len;
    memcpy(msg + mlen, k3_qkd,                          QKD_KEY_SIZE);           mlen += QKD_KEY_SIZE;

    /* Deniable ring: {client_pk, server_pk} */
    uint8_t ring_keys[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(ring_keys,                          client_pk_gandalf,               GANDALF_PUBLIC_KEY_SIZE);
    memcpy(ring_keys + GANDALF_PUBLIC_KEY_SIZE, server_keys->gandalf.public_key, GANDALF_PUBLIC_KEY_SIZE);

    gandalf_ring_t ring = {
        .ring_public_keys = ring_keys,
        .ring_size        = 2,
        .signer_index     = 0
    };

    if (gandalf_verify(msg, mlen, client_hello->signature, &ring) != 0) {
        return HDKEM_ERROR_VERIFICATION;
    }

    if (mlkem768_decapsulate(server_keys->mlkem.secret_key,
                             client_hello->mlkem_ciphertext,
                             session->k1) != 0)
        return HDKEM_ERROR_DECAPSULATION;

    if (x25519_shared_secret(server_keys->x25519.secret_key,
                             client_hello->x25519_public_key,
                             session->k2) != 0)
        return HDKEM_ERROR_DECAPSULATION;

    memcpy(session->k3, k3_qkd, QKD_KEY_SIZE);

    if (hdkem_derive_session_key(session->k1, session->k2, session->k3,
                                 client_hello->signature, GANDALF_SIGNATURE_SIZE,
                                 client_hello->mlkem_ciphertext, MLKEM_CIPHERTEXT_SIZE,
                                 client_hello->x25519_public_key,
                                 client_hello->client_id, client_hello->client_id_len,
                                 server_keys->id, server_keys->id_len,
                                 session->session_key) != 0)
        return HDKEM_ERROR_KDF;



    if (random_bytes(session->nonce, ASCON_NONCE_SIZE) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    session->is_established = 1;
    return HDKEM_SUCCESS;
}

/* ===== Client-Side Implementation ===== */

int hdkem_client_init(hdkem_client_keys_t *client_keys,
                      const uint8_t *id, size_t id_len)
{
    if (!client_keys || !id || id_len == 0 || id_len > MAX_ID_SIZE)
        return HDKEM_ERROR_INVALID_PARAM;

    if (x25519_keypair(client_keys->x25519.public_key,
                       client_keys->x25519.secret_key) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    if (gandalf_keypair(client_keys->gandalf.public_key,
                        client_keys->gandalf.secret_key) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    memcpy(client_keys->id, id, id_len);
    client_keys->id_len = id_len;
    return HDKEM_SUCCESS;
}

int hdkem_client_process_server_hello(hdkem_client_keys_t *client_keys,
                                       const hdkem_server_hello_t *server_hello,
                                       const uint8_t *server_pk_gandalf,
                                       const uint8_t *k3_qkd,
                                       hdkem_client_hello_t *client_hello,
                                       hdkem_session_t *session)
{
    if (!client_keys || !server_hello || !server_pk_gandalf ||
        !k3_qkd || !client_hello || !session)
        return HDKEM_ERROR_INVALID_PARAM;

    /* Verify server hello — ring R = {server_pk, client_pk}
     * Paper §4: sig_s signed with R = {k_pub_s3, k_pub_r3}. */
    uint8_t msg_verify[MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE + MAX_ID_SIZE];
    size_t mvlen = 0;
    memcpy(msg_verify + mvlen, server_hello->mlkem_public_key,  MLKEM_PUBLIC_KEY_SIZE);  mvlen += MLKEM_PUBLIC_KEY_SIZE;
    memcpy(msg_verify + mvlen, server_hello->x25519_public_key, X25519_PUBLIC_KEY_SIZE); mvlen += X25519_PUBLIC_KEY_SIZE;
    memcpy(msg_verify + mvlen, server_hello->server_id, server_hello->server_id_len);    mvlen += server_hello->server_id_len;

    /* R = {server_pk, client_pk} matching how server signed */
    uint8_t ring_keys_s[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(ring_keys_s,                          server_pk_gandalf,              GANDALF_PUBLIC_KEY_SIZE);
    memcpy(ring_keys_s + GANDALF_PUBLIC_KEY_SIZE, client_keys->gandalf.public_key, GANDALF_PUBLIC_KEY_SIZE);

    gandalf_ring_t ring_server = {
        .ring_public_keys = ring_keys_s,
        .ring_size        = 2,
        .signer_index     = 0
    };

    if (gandalf_verify(msg_verify, mvlen, server_hello->signature, &ring_server) != 0) {
        return HDKEM_ERROR_VERIFICATION;
    }

    /* Encapsulate ML-KEM */
    if (mlkem768_encapsulate(server_hello->mlkem_public_key,
                             client_hello->mlkem_ciphertext,
                             session->k1) != 0)
        return HDKEM_ERROR_ENCAPSULATION;

    /* X25519 shared secret */
    if (x25519_shared_secret(client_keys->x25519.secret_key,
                             server_hello->x25519_public_key,
                             session->k2) != 0)
        return HDKEM_ERROR_ENCAPSULATION;

    memcpy(session->k3, k3_qkd, QKD_KEY_SIZE);

    /* Fill client hello */
    memcpy(client_hello->x25519_public_key, client_keys->x25519.public_key, X25519_PUBLIC_KEY_SIZE);
    memcpy(client_hello->client_id,         client_keys->id,               client_keys->id_len);
    client_hello->client_id_len = client_keys->id_len;

    /* Sign: c || k_pub_r2 || ID_S || ID_C || k3
     * Paper §4: sig_r = RingSign(R, k_pr_r3, c||k_pub_r2||ID_S||ID_C||k3)
     * k_pub_r2 is the client's ephemeral X25519 public key.
     */
    uint8_t msg_sign[MLKEM_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE +
                     MAX_ID_SIZE + MAX_ID_SIZE + QKD_KEY_SIZE];
    size_t mslen = 0;
    memcpy(msg_sign + mslen, client_hello->mlkem_ciphertext,  MLKEM_CIPHERTEXT_SIZE);  mslen += MLKEM_CIPHERTEXT_SIZE;
    memcpy(msg_sign + mslen, client_hello->x25519_public_key, X25519_PUBLIC_KEY_SIZE); mslen += X25519_PUBLIC_KEY_SIZE;
    memcpy(msg_sign + mslen, server_hello->server_id,         server_hello->server_id_len); mslen += server_hello->server_id_len;
    memcpy(msg_sign + mslen, client_hello->client_id,         client_hello->client_id_len); mslen += client_hello->client_id_len;
    memcpy(msg_sign + mslen, k3_qkd,                          QKD_KEY_SIZE);           mslen += QKD_KEY_SIZE;

    uint8_t ring_keys_c[2 * GANDALF_PUBLIC_KEY_SIZE];
    memcpy(ring_keys_c,                          client_keys->gandalf.public_key, GANDALF_PUBLIC_KEY_SIZE);
    memcpy(ring_keys_c + GANDALF_PUBLIC_KEY_SIZE, server_pk_gandalf,              GANDALF_PUBLIC_KEY_SIZE);

    gandalf_ring_t ring_client = {
        .ring_public_keys = ring_keys_c,
        .ring_size        = 2,
        .signer_index     = 0  /* client is index 0 */
    };

    if (gandalf_sign(client_keys->gandalf.secret_key, msg_sign, mslen,
                     &ring_client, client_hello->signature) != 0)
        return HDKEM_ERROR_SIGNATURE;

    client_hello->signature_len = GANDALF_SIGNATURE_SIZE;

    if (hdkem_derive_session_key(session->k1, session->k2, session->k3,
                                 client_hello->signature, client_hello->signature_len,
                                 client_hello->mlkem_ciphertext, MLKEM_CIPHERTEXT_SIZE,
                                 client_hello->x25519_public_key,
                                 client_hello->client_id, client_hello->client_id_len,
                                 server_hello->server_id, server_hello->server_id_len,
                                 session->session_key) != 0)
        return HDKEM_ERROR_KDF;



    if (random_bytes(session->nonce, ASCON_NONCE_SIZE) != 0)
        return HDKEM_ERROR_KEY_GENERATION;

    session->is_established = 1;
    return HDKEM_SUCCESS;
}

/* ===== Session Key Derivation — split-key PRF =====
 *
 * ksh = skPRF(k1, k2, k3 ; sig || ct || IDC || IDS)
 *
 * The context (sig||ct||IDC||IDS) is passed as the "ctx" argument to
 * _skprf() so that different sessions always produce different keys even
 * if the same (k1,k2,k3) triple is reused (e.g. in replays).
 */
int hdkem_derive_session_key(const uint8_t *k1,
                             const uint8_t *k2,
                             const uint8_t *k3,
                             const uint8_t *signature, size_t sig_len,
                             const uint8_t *ciphertext, size_t ct_len,
                             const uint8_t *client_x25519_pk,
                             const uint8_t *client_id, size_t client_id_len,
                             const uint8_t *server_id, size_t server_id_len,
                             uint8_t *session_key)
{
    if (!k1||!k2||!k3||!signature||!ciphertext||
        !client_x25519_pk||!client_id||!server_id||!session_key)
        return HDKEM_ERROR_INVALID_PARAM;

    /*
     * Paper Eq.(1): τ = c || k_pub_r2 || ID_C || ID_S || sig_r
     * ksh = skPRF(k1, k2, k3; τ)
     * where k_pub_r2 = client ephemeral X25519 public key (32 bytes).
     * sig_r is bound LAST in τ, giving injective session agreement.
     */
    size_t ctx_len = ct_len + X25519_PUBLIC_KEY_SIZE
                     + client_id_len + server_id_len + sig_len;
    if (ctx_len > 65535) return HDKEM_ERROR_INVALID_PARAM;

    uint8_t *ctx = malloc(ctx_len);
    if (!ctx) return HDKEM_ERROR_KDF;

    size_t off = 0;
    memcpy(ctx + off, ciphertext,       ct_len);               off += ct_len;
    memcpy(ctx + off, client_x25519_pk, X25519_PUBLIC_KEY_SIZE); off += X25519_PUBLIC_KEY_SIZE;
    memcpy(ctx + off, client_id,        client_id_len);        off += client_id_len;
    memcpy(ctx + off, server_id,        server_id_len);        off += server_id_len;
    memcpy(ctx + off, signature,        sig_len);

    int rc = _skprf(NULL, k1, k2, k3, ctx, ctx_len, session_key, SESSION_KEY_SIZE);

    hdkem_secure_memzero(ctx, ctx_len);
    free(ctx);
    return (rc == 0) ? HDKEM_SUCCESS : HDKEM_ERROR_KDF;
}

/* ===== Secure Communication ===== */

int hdkem_encrypt_message(const hdkem_session_t *session,
                          const uint8_t *plaintext, size_t ptlen,
                          hdkem_encrypted_msg_t *encrypted)
{
    if (!session||!session->is_established||!plaintext||
        !encrypted||ptlen>MAX_MESSAGE_SIZE)
        return HDKEM_ERROR_INVALID_PARAM;

    memcpy(encrypted->nonce, session->nonce, ASCON_NONCE_SIZE);

    uint8_t tag[ASCON_TAG_SIZE];
    if (ascon_encrypt(session->session_key, encrypted->nonce,
                      plaintext, ptlen, NULL, 0,
                      encrypted->ciphertext, tag) != 0)
        return HDKEM_ERROR_ENCRYPTION;

    memcpy(encrypted->ciphertext + ptlen, tag, ASCON_TAG_SIZE);
    encrypted->ciphertext_len = ptlen + ASCON_TAG_SIZE;
    return HDKEM_SUCCESS;
}

int hdkem_decrypt_message(const hdkem_session_t *session,
                          const hdkem_encrypted_msg_t *encrypted,
                          uint8_t *plaintext, size_t *plaintext_len)
{
    if (!session||!session->is_established||!encrypted||
        !plaintext||!plaintext_len)
        return HDKEM_ERROR_INVALID_PARAM;

    if (encrypted->ciphertext_len < ASCON_TAG_SIZE)
        return HDKEM_ERROR_DECRYPTION;

    size_t ct_len = encrypted->ciphertext_len - ASCON_TAG_SIZE;
    const uint8_t *tag = encrypted->ciphertext + ct_len;

    if (ascon_decrypt(session->session_key, encrypted->nonce,
                      encrypted->ciphertext, ct_len, NULL, 0,
                      tag, plaintext) != 0)
        return HDKEM_ERROR_DECRYPTION;

    *plaintext_len = ct_len;
    return HDKEM_SUCCESS;
}

/* ===== Utility Functions ===== */

void hdkem_secure_memzero(void *ptr, size_t len) {
    if (ptr) { volatile uint8_t *p=(volatile uint8_t*)ptr; while(len--)*p++=0; }
}

int hdkem_constant_time_compare(const void *a, const void *b, size_t len) {
    const uint8_t *aa=(const uint8_t*)a, *bb=(const uint8_t*)b;
    uint8_t r=0;
    for (size_t i=0;i<len;i++) r|=aa[i]^bb[i];
    return r==0?0:-1;
}
