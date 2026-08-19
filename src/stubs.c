/* Functional stubs: real enough that a handshake either succeeds or fails
   for protocol reasons, not cryptographic ones. */
#include "hdkem_primitives.h"
#include <oqs/oqs.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

static uint32_t rs = 987654321u;
static uint32_t nx(void){ rs ^= rs<<13; rs ^= rs>>17; rs ^= rs<<5; return rs; }
int sodium_init(void){ return 0; }
void sodium_memzero(void*p,size_t n){ memset(p,0,n); }
void randombytes_buf(void*p,size_t n){ unsigned char*b=p; for(size_t i=0;i<n;i++) b[i]=(unsigned char)nx(); }
int random_bytes(uint8_t*b,size_t n){ randombytes_buf(b,n); return 0; }

/* deterministic "hash" — collision-prone but order/содержание sensitive */
static void mix(const uint8_t*d,size_t n,uint8_t*st){ for(size_t i=0;i<n;i++){ st[i%32]^=d[i]; st[(i+7)%32]=(uint8_t)(st[(i+7)%32]*31+d[i]+1);} }
typedef struct { uint8_t s[32]; } shk;
void OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx*c){ c->st=calloc(1,sizeof(shk)); }
void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx*c,const uint8_t*d,size_t n){ mix(d,n,((shk*)c->st)->s); }
void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx*c){ (void)c; }
void OQS_SHA3_shake256_inc_squeeze(uint8_t*o,size_t n,OQS_SHA3_shake256_inc_ctx*c){ shk*s=c->st; for(size_t i=0;i<n;i++){ o[i]=(uint8_t)(s->s[i%32]+i*7); } }
void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx*c){ free(c->st); }

int mlkem768_keypair(uint8_t*pk,uint8_t*sk){ randombytes_buf(sk,MLKEM_SECRET_KEY_SIZE); for(int i=0;i<MLKEM_PUBLIC_KEY_SIZE;i++) pk[i]=sk[i%64]; return 0; }
int mlkem768_encapsulate(const uint8_t*pk,uint8_t*ct,uint8_t*ss){ for(int i=0;i<MLKEM_CIPHERTEXT_SIZE;i++) ct[i]=pk[i%MLKEM_PUBLIC_KEY_SIZE]; for(int i=0;i<32;i++) ss[i]=pk[i]; return 0; }
int mlkem768_decapsulate(const uint8_t*sk,const uint8_t*ct,uint8_t*ss){ (void)ct; for(int i=0;i<32;i++) ss[i]=sk[i%64]; return 0; }
int x25519_keypair(uint8_t*pk,uint8_t*sk){ randombytes_buf(sk,32); for(int i=0;i<32;i++) pk[i]=(uint8_t)(sk[i]^0x5A); return 0; }
int x25519_shared_secret(const uint8_t*sk,const uint8_t*pk,uint8_t*ss){ for(int i=0;i<32;i++) ss[i]=(uint8_t)(sk[i]^pk[i]); return 0; }
int gandalf_keypair(uint8_t*pk,uint8_t*sk){ randombytes_buf(sk,GANDALF_SECRET_KEY_SIZE); for(int i=0;i<GANDALF_PUBLIC_KEY_SIZE;i++) pk[i]=sk[i%128]; return 0; }
int gandalf_sign(const uint8_t*sk,const uint8_t*m,size_t ml,const gandalf_ring_t*r,uint8_t*sig){
  if(!r||r->ring_size!=2) return -1;
  memset(sig,0,GANDALF_SIGNATURE_SIZE);
  for(size_t i=0;i<ml && i<GANDALF_SIGNATURE_SIZE-8;i++) sig[i]=(uint8_t)(m[i]^sk[i%128]);
  sig[GANDALF_SIGNATURE_SIZE-1]=(uint8_t)r->signer_index; return 0; }
int gandalf_verify(const uint8_t*m,size_t ml,const uint8_t*sig,const gandalf_ring_t*r){
  if(!r||r->ring_size!=2) return -1;
  (void)m;(void)ml;
  return sig[GANDALF_SIGNATURE_SIZE-1]==(uint8_t)r->signer_index?0:-1; }
int hmac_sha256(const uint8_t*k,size_t kl,const uint8_t*m,size_t ml,uint8_t*o){ (void)k;(void)kl;(void)m;(void)ml; memset(o,7,32); return 0; }
int hkdf_extract(const uint8_t*s,size_t sl,const uint8_t*i,size_t il,uint8_t*p){ (void)s;(void)sl;(void)i;(void)il; memset(p,3,32); return 0; }
int hkdf_expand(const uint8_t*p,size_t pl,const uint8_t*i,size_t il,uint8_t*o,size_t ol){ (void)p;(void)pl;(void)i;(void)il; memset(o,5,ol); return 0; }
int hkdf(const uint8_t*s,size_t sl,const uint8_t*i,size_t il,const uint8_t*n,size_t nl,uint8_t*o,size_t ol){ (void)s;(void)sl;(void)n;(void)nl; for(size_t j=0;j<ol;j++) o[j]=(uint8_t)(il?i[j%il]+j:j); return 0; }
int ascon_encrypt(const uint8_t*k,const uint8_t*nn,const uint8_t*pt,size_t pl,const uint8_t*ad,size_t al,uint8_t*ct,uint8_t*tag){
  (void)ad;(void)al; for(size_t i=0;i<pl;i++) ct[i]=(uint8_t)(pt[i]^k[i%16]^nn[i%16]);
  for(int i=0;i<16;i++) tag[i]=(uint8_t)(k[i]^nn[i]^(uint8_t)pl); return 0; }
int ascon_decrypt(const uint8_t*k,const uint8_t*nn,const uint8_t*ct,size_t cl,const uint8_t*ad,size_t al,const uint8_t*tag,uint8_t*pt){
  (void)ad;(void)al; uint8_t e[16]; for(int i=0;i<16;i++) e[i]=(uint8_t)(k[i]^nn[i]^(uint8_t)cl);
  if(memcmp(e,tag,16)!=0) return -1;
  for(size_t i=0;i<cl;i++) pt[i]=(uint8_t)(ct[i]^k[i%16]^nn[i%16]); return 0; }
double qkd_calculate_secret_key_rate(const qkd_params_t*p){ (void)p; return 0.44; }
static uint8_t shared_k3[64]; static int k3_init=0;
int qkd_establish_key(const qkd_params_t*p,uint8_t*k,size_t n){
  if(!p||p->qber>=0.11) return -1;
  if(!k3_init){ for(int i=0;i<64;i++) shared_k3[i]=(uint8_t)(i*11+3); k3_init=1; }
  memcpy(k,shared_k3,n); return 0; }
