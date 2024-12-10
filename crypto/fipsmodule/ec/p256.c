/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// An implementation of the NIST P-256 elliptic curve point multiplication.
// 256-bit Montgomery form for 64 and 32-bit. Field operations are generated by
// Fiat, which lives in //third_party/fiat.

#include <openssl/base.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/mem.h>

#include <assert.h>

#include "../../internal.h"
#include "../delocate.h"
#include "./internal.h"

#define P256_LIMBS (32 / sizeof(crypto_word_t))
typedef crypto_word_t fiat_p256_felem[P256_LIMBS];

#if defined(OPENSSL_64_BIT)
#if defined(BORINGSSL_HAS_UINT128)
#include "../../../third_party/fiat/p256_64.h"
#else
#include "../../../third_party/fiat/p256_64_msvc.h"
#endif
static const fiat_p256_felem fiat_p256_one = {0x1, 0xffffffff00000000,
                                              0xffffffffffffffff, 0xfffffffe};
#elif defined(OPENSSL_32_BIT)
#include "../../../third_party/fiat/p256_32.h"
static const fiat_p256_felem fiat_p256_one = {
    0x1, 0x0, 0x0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x0};
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif

/////////////////////////////////

static inline void fe_sub(uintptr_t out, uintptr_t x, uintptr_t y) { fiat_p256_sub((crypto_word_t*)out, (crypto_word_t*)x, (crypto_word_t*)y); }
static inline void fe_add(uintptr_t out, uintptr_t x, uintptr_t y) { fiat_p256_add((crypto_word_t*)out, (crypto_word_t*)x, (crypto_word_t*)y); }
static inline void fe_mul(uintptr_t out, uintptr_t x, uintptr_t y) { fiat_p256_mul((crypto_word_t*)out, (crypto_word_t*)x, (crypto_word_t*)y); }
static inline void fe_sqr(uintptr_t out, uintptr_t x) { fiat_p256_square((crypto_word_t*)out, (crypto_word_t*)x); }

/////////////////////////////////

// We use memcpy to work around -fstrict-aliasing.
// A plain memcpy is enough on clang 10, but not on gcc 10, which fails
// to infer the bounds on an integer loaded by memcpy.
// Adding a range mask after memcpy in turn makes slower code in clang.
// Loading individual bytes, shifting them together, and or-ing is fast
// on clang and sometimes on GCC, but other times GCC inlines individual
// byte operations without reconstructing wider accesses.
// The little-endian idiom below seems fast in gcc 9+ and clang 10.
static inline  __attribute__((always_inline, unused))
uintptr_t _br2_load(uintptr_t a, uintptr_t sz) {
  switch (sz) {
  case 1: { uint8_t  r = 0; memcpy(&r, (void*)a, 1); return r; }
  case 2: { uint16_t r = 0; memcpy(&r, (void*)a, 2); return r; }
  case 4: { uint32_t r = 0; memcpy(&r, (void*)a, 4); return r; }
  case 8: { uint64_t r = 0; memcpy(&r, (void*)a, 8); return r; }
  default: __builtin_unreachable();
  }
}

static inline __attribute__((always_inline, unused))
void _br2_store(uintptr_t a, uintptr_t v, uintptr_t sz) {
  memcpy((void*)a, &v, sz);
}

static inline __attribute__((always_inline, unused))
uintptr_t _br2_mulhuu(uintptr_t a, uintptr_t b) {
  #if (UINTPTR_MAX == (UINTMAX_C(1)<<31) - 1 + (UINTMAX_C(1)<<31))
	  return ((uint64_t)a * b) >> 32;
  #elif (UINTPTR_MAX == (UINTMAX_C(1)<<63) - 1 + (UINTMAX_C(1)<<63))
    return ((unsigned __int128)a * b) >> 64;
  #else
    #error ""32-bit or 64-bit uintptr_t required""
  #endif
}

static inline __attribute__((always_inline, unused))
uintptr_t _br2_divu(uintptr_t a, uintptr_t b) {
  if (!b) return -1;
  return a/b;
}

static inline __attribute__((always_inline, unused))
uintptr_t _br2_remu(uintptr_t a, uintptr_t b) {
  if (!b) return a;
  return a%b;
}

static inline __attribute__((always_inline, unused))
uintptr_t _br2_shamt(uintptr_t a) {
  return a&(sizeof(uintptr_t)*8-1);
}

static void fiat_p256_point_add_affine_nz_nz_neq(uintptr_t out, uintptr_t in1, uintptr_t in2) {
  uintptr_t z1z1, Hsqr, u2, Hcub, r, h, s2;
  { uint8_t _br2_stackalloc_z1z1[(uintptr_t)(UINTMAX_C(32))] = {0}; z1z1 = (uintptr_t)&_br2_stackalloc_z1z1;
  { uint8_t _br2_stackalloc_u2[(uintptr_t)(UINTMAX_C(32))] = {0}; u2 = (uintptr_t)&_br2_stackalloc_u2;
  { uint8_t _br2_stackalloc_h[(uintptr_t)(UINTMAX_C(32))] = {0}; h = (uintptr_t)&_br2_stackalloc_h;
  { uint8_t _br2_stackalloc_s2[(uintptr_t)(UINTMAX_C(32))] = {0}; s2 = (uintptr_t)&_br2_stackalloc_s2;
  { uint8_t _br2_stackalloc_r[(uintptr_t)(UINTMAX_C(32))] = {0}; r = (uintptr_t)&_br2_stackalloc_r;
  { uint8_t _br2_stackalloc_Hsqr[(uintptr_t)(UINTMAX_C(32))] = {0}; Hsqr = (uintptr_t)&_br2_stackalloc_Hsqr;
  { uint8_t _br2_stackalloc_Hcub[(uintptr_t)(UINTMAX_C(32))] = {0}; Hcub = (uintptr_t)&_br2_stackalloc_Hcub;
  fe_sqr(z1z1, ((in1)+((uintptr_t)(UINTMAX_C(32))))+((uintptr_t)(UINTMAX_C(32))));
  fe_mul(u2, in2, z1z1);
  fe_sub(h, u2, in1);
  fe_mul(s2, ((in1)+((uintptr_t)(UINTMAX_C(32))))+((uintptr_t)(UINTMAX_C(32))), z1z1);
  fe_mul(((out)+((uintptr_t)(UINTMAX_C(32))))+((uintptr_t)(UINTMAX_C(32))), h, ((in1)+((uintptr_t)(UINTMAX_C(32))))+((uintptr_t)(UINTMAX_C(32))));
  fe_mul(s2, s2, (in2)+((uintptr_t)(UINTMAX_C(32))));
  fe_sub(r, s2, (in1)+((uintptr_t)(UINTMAX_C(32))));
  fe_sqr(Hsqr, h);
  fe_sqr(out, r);
  fe_mul(Hcub, Hsqr, h);
  fe_mul(u2, in1, Hsqr);
  fe_sub(out, out, Hcub);
  fe_sub(out, out, u2);
  fe_sub(out, out, u2);
  fe_sub(h, u2, out);
  fe_mul(s2, Hcub, (in1)+((uintptr_t)(UINTMAX_C(32))));
  fe_mul(h, h, r);
  fe_sub((out)+((uintptr_t)(UINTMAX_C(32))), h, s2);
  }
  }
  }
  }
  }
  }
  }
  return;
}

////////////////////////////////////

static crypto_word_t fiat_p256_is_zero(const fiat_p256_felem x) {
  crypto_word_t ret;
  fiat_p256_nonzero(&ret, x);
  return constant_time_is_zero_w(ret);
}

// this function is faster than constant_time_conditional_memcpy when the
// inputs are already in general-purpose registers, or when some inputs are
// constants for which the bitwise selection can be simplified.
static void fiat_p256_conditional_copy(fiat_p256_felem x,
                                       const fiat_p256_felem y,
                                       crypto_word_t t) {
  fiat_p256_selectznz(x, !!t, x, y);
}

static void fiat_p256_opp_conditional(fiat_p256_felem x, crypto_word_t c) {
  fiat_p256_felem alignas(32) n;
  fiat_p256_opp(n, x);
  fiat_p256_conditional_copy(x, n, c);
}

static void fiat_p256_conditional_zero_or_one(fiat_p256_felem x,
                                              crypto_word_t c) {
  OPENSSL_memset(x, 0, sizeof(fiat_p256_felem));
  fiat_p256_conditional_copy(x, fiat_p256_one, c);
}

static void fiat_p256_from_words(fiat_p256_felem out,
                                 const BN_ULONG in[32 / sizeof(BN_ULONG)]) {
  OPENSSL_memcpy(out, in, 32);
}

static void fiat_p256_from_generic(fiat_p256_felem out, const EC_FELEM *in) {
  fiat_p256_from_words(out, in->words);
}

static void fiat_p256_to_generic(EC_FELEM *out, const fiat_p256_felem in) {
  OPENSSL_memcpy(out->words, in, 32);
}

// fiat_p256_inv_square calculates |out| = |in|^{-2}
//
// Based on Fermat's Little Theorem:
//   a^p = a (mod p)
//   a^{p-1} = 1 (mod p)
//   a^{p-3} = a^{-2} (mod p)
static void fiat_p256_inv_square(fiat_p256_felem out,
                                 const fiat_p256_felem in) {
  // This implements the addition chain described in
  // https://briansmith.org/ecc-inversion-addition-chains-01#p256_field_inversion
  fiat_p256_felem x2, x3, x6, x12, x15, x30, x32;
  fiat_p256_square(x2, in);   // 2^2 - 2^1
  fiat_p256_mul(x2, x2, in);  // 2^2 - 2^0

  fiat_p256_square(x3, x2);   // 2^3 - 2^1
  fiat_p256_mul(x3, x3, in);  // 2^3 - 2^0

  fiat_p256_square(x6, x3);
  for (int i = 1; i < 3; i++) {
    fiat_p256_square(x6, x6);
  }                           // 2^6 - 2^3
  fiat_p256_mul(x6, x6, x3);  // 2^6 - 2^0

  fiat_p256_square(x12, x6);
  for (int i = 1; i < 6; i++) {
    fiat_p256_square(x12, x12);
  }                             // 2^12 - 2^6
  fiat_p256_mul(x12, x12, x6);  // 2^12 - 2^0

  fiat_p256_square(x15, x12);
  for (int i = 1; i < 3; i++) {
    fiat_p256_square(x15, x15);
  }                             // 2^15 - 2^3
  fiat_p256_mul(x15, x15, x3);  // 2^15 - 2^0

  fiat_p256_square(x30, x15);
  for (int i = 1; i < 15; i++) {
    fiat_p256_square(x30, x30);
  }                              // 2^30 - 2^15
  fiat_p256_mul(x30, x30, x15);  // 2^30 - 2^0

  fiat_p256_square(x32, x30);
  fiat_p256_square(x32, x32);   // 2^32 - 2^2
  fiat_p256_mul(x32, x32, x2);  // 2^32 - 2^0

  fiat_p256_felem ret;
  fiat_p256_square(ret, x32);
  for (int i = 1; i < 31 + 1; i++) {
    fiat_p256_square(ret, ret);
  }                             // 2^64 - 2^32
  fiat_p256_mul(ret, ret, in);  // 2^64 - 2^32 + 2^0

  for (int i = 0; i < 96 + 32; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^192 - 2^160 + 2^128
  fiat_p256_mul(ret, ret, x32);  // 2^192 - 2^160 + 2^128 + 2^32 - 2^0

  for (int i = 0; i < 32; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^224 - 2^192 + 2^160 + 2^64 - 2^32
  fiat_p256_mul(ret, ret, x32);  // 2^224 - 2^192 + 2^160 + 2^64 - 2^0

  for (int i = 0; i < 30; i++) {
    fiat_p256_square(ret, ret);
  }                              // 2^254 - 2^222 + 2^190 + 2^94 - 2^30
  fiat_p256_mul(ret, ret, x30);  // 2^254 - 2^222 + 2^190 + 2^94 - 2^0

  fiat_p256_square(ret, ret);
  fiat_p256_square(out, ret);  // 2^256 - 2^224 + 2^192 + 2^96 - 2^2
}

static inline uint64_t shrd_64(uint64_t lo, uint64_t hi, uint64_t n) {
  return (((uint128_t)hi << 64) | (uint128_t)lo) >> (n&63);
}

static void fiat_p256_halve(fiat_p256_felem y, const fiat_p256_felem x) {
  static const fiat_p256_felem minus_half = {
    -UINT64_C(1), -UINT64_C(1) >> 33, -UINT64_C(1) << 63, -UINT64_C(1) << 32 >> 1};
  fiat_p256_felem maybe_minus_half = {0};
  fiat_p256_conditional_copy(maybe_minus_half, minus_half, x[0] & 1);

  y[0] = shrd_64(y[0], y[1], 1);
  y[1] = shrd_64(y[1], y[2], 1);
  y[2] = shrd_64(y[2], y[3], 1);
  y[3] = y[3] >> 1;
  fiat_p256_sub(y, y, maybe_minus_half);
}

// Group operations
// ----------------
//
// Building on top of the field operations we have the operations on the
// elliptic curve group itself. Points on the curve are represented in Jacobian
// coordinates.

// Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed.
// while x_out == y_in is not (maybe this works, but it's not tested).

// Addition operation was transcribed to Coq and proven to correspond to naive
// implementations using Affine coordinates, for all suitable fields.  In the
// Coq proofs, issues of constant-time execution and memory layout (aliasing)
// conventions were not considered. Specification of affine coordinates:
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Spec/WeierstrassCurve.v#L28>
// As a sanity check, a proof that these points form a commutative group:
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Curves/Weierstrass/AffineProofs.v#L33>

static void fiat_p256_point_double(fiat_p256_felem out[3],
                                   const fiat_p256_felem in[3]) {
  fiat_p256_felem D, A, tmp; // HMV'04p91
  fiat_p256_add(D, in[1], in[1]); // B
  fiat_p256_square(tmp, in[2]);
  fiat_p256_square(D, D); // C
  fiat_p256_mul(out[2], in[2], in[1]);
  fiat_p256_add(out[2], out[2], out[2]);
  fiat_p256_add(A, in[0], tmp);
  fiat_p256_sub(tmp, in[0], tmp);
  fiat_p256_felem t2; fiat_p256_add(t2, tmp, tmp); fiat_p256_add(tmp, t2, tmp);
  fiat_p256_square(out[1], D);
  fiat_p256_mul(A, A, tmp);
  fiat_p256_mul(D, D, in[0]); // D
  fiat_p256_square(out[0], A);
  fiat_p256_add(tmp, D, D);
  fiat_p256_sub(out[0], out[0], tmp);
  fiat_p256_sub(D, D, out[0]);
  fiat_p256_mul(D, D, A);
  fiat_p256_halve(out[1], out[1]); // C^2/2
  fiat_p256_sub(out[1], D, out[1]);
}

// fiat_p256_point_add calculates (x1, y1, z1) + (x2, y2, z2)
// returns -1 and an incorrect point if the input points are equal.
#if defined(__GNUC__) && !defined(OPENSSL_SMALL)
__attribute__((always_inline)) // 0.5% on P-256 ECDH
#endif
static crypto_word_t fiat_p256_point_add_nz_nz_neq(fiat_p256_felem out[3],
                                                   const fiat_p256_felem in1[3],
                                                   const int p2affine,
                                                   const fiat_p256_felem *in2) {
  fiat_p256_felem z1z1, z2z2, u1, u2, h, s1, s2, r, Hsqr, Hcub; // HMV'04p89.14
  fiat_p256_square(z1z1, in1[2]);  // A = Z^2
  fiat_p256_mul(u2, in2[0], z1z1);  // C = X2*A
  if (p2affine) {
    OPENSSL_memcpy(u1, in1[0], sizeof(u1));
  } else {
    fiat_p256_square(z2z2, in2[2]);
    fiat_p256_mul(u1, in1[0], z2z2);
  }
  fiat_p256_sub(h, u2, u1);  // E = C - X1
  fiat_p256_mul(s2, in1[2], z1z1);  // B + Z1*A
  fiat_p256_mul(out[2], h, in1[2]);  // Z3 = E*Z1
  if (!p2affine) {
    fiat_p256_mul(out[2], out[2], in2[2]);
  }
  fiat_p256_mul(s2, s2, in2[1]);  // D = Y2 * B
  if (p2affine) {  // Z2 == 1
    OPENSSL_memcpy(s1, in1[1], sizeof(s1));
  } else {
    fiat_p256_mul(s1, in2[2], z2z2); // in1[1] * z2**3
    fiat_p256_mul(s1, s1, in1[1]);
  }
  fiat_p256_sub(r, s2, s1);  // F = D - Y1
  crypto_word_t doubling = fiat_p256_is_zero(h) & fiat_p256_is_zero(r);
  fiat_p256_square(Hsqr, h);  // G = E^2
  fiat_p256_square(out[0], r);  // F^2
  fiat_p256_mul(Hcub, Hsqr, h);  // H = G*E
  fiat_p256_mul(u2, u1, Hsqr);  // I = X1 * G
  fiat_p256_sub(out[0], out[0], Hcub);
  fiat_p256_sub(out[0], out[0], u2);
  fiat_p256_sub(out[0], out[0], u2);
  fiat_p256_sub(h, u2, out[0]);
  fiat_p256_mul(s2, Hcub, s1);  // Y1 * H
  fiat_p256_mul(h, h, r);       // E * F
  fiat_p256_sub(out[1], h, s2);
  return doubling;
}

// returns -1 and incorrect output if the input points are equal and nonzero.
static crypto_word_t fiat_p256_point_add_nnteq(fiat_p256_felem out[3],
                                               const fiat_p256_felem in1[3],
                                               const fiat_p256_felem in2[3]) {
  crypto_word_t p1zero = fiat_p256_is_zero(in1[2]);
  crypto_word_t p2zero = fiat_p256_is_zero(in2[2]);
  fiat_p256_felem p_out[3];
  crypto_word_t doubling = fiat_p256_point_add_nz_nz_neq(p_out, in1, 0, in2);
  fiat_p256_felem t[3] = {{0}, {0}, {0}};
  constant_time_conditional_memxor(t, p_out, sizeof(t), ~p1zero & ~p2zero);
  constant_time_conditional_memxor(t, in1,   sizeof(t), ~p1zero &  p2zero);
  constant_time_conditional_memxor(t, in2,   sizeof(t),  p1zero & ~p2zero);
  OPENSSL_memcpy(out, t, sizeof(t));
  return doubling & ~(p1zero | p2zero); // nontrivial doubling, wrong output
}

__attribute__((noinline))
static void fiat_p256_point_add(fiat_p256_felem out[3],
                                const fiat_p256_felem in1[3],
                                const fiat_p256_felem in2[3]) {
  crypto_word_t nontrivial_doubling = fiat_p256_point_add_nnteq(out, in1, in2);
  (void)nontrivial_doubling; assert(!nontrivial_doubling);
}

__attribute__((noinline))
static void fiat_p256_point_add_nz_nz(fiat_p256_felem out[3],
                                      const fiat_p256_felem in1[3],
                                      const fiat_p256_felem in2[3]) {
  assert(!fiat_p256_is_zero(in1[2]));
  assert(!fiat_p256_is_zero(in2[2]));
  fiat_p256_felem t[3];
  fiat_p256_point_add_nz_nz_neq(t, in1, 0, in2);
  OPENSSL_memcpy(out, t, sizeof(t));
}

__attribute__((noinline))
static void fiat_p256_point_add_nz(fiat_p256_felem out[3],
                                   const fiat_p256_felem in1[3],
                                   const fiat_p256_felem in2[3]) {
  assert(!fiat_p256_is_zero(in2[2]));
  fiat_p256_felem t[3];
  crypto_word_t p1zero = fiat_p256_is_zero(in1[2]);
  fiat_p256_point_add_nz_nz_neq(t, in1, 0, in2);
  constant_time_conditional_memcpy(t, in2, sizeof(t), p1zero);
  OPENSSL_memcpy(out, t, sizeof(t));
}

__attribute__((noinline))
static void fiat_p256_point_add_affine_nz(fiat_p256_felem out[3],
                                          const fiat_p256_felem in1[3],
                                          const fiat_p256_felem in2[2]) {
  fiat_p256_felem t[3];
  crypto_word_t p1zero = fiat_p256_is_zero(in1[2]);
  fiat_p256_point_add_affine_nz_nz_neq((uintptr_t)t, (uintptr_t)in1, (uintptr_t)in2);
  //fiat_p256_point_add_nz_nz_neq(t, in1, 1, in2);
  constant_time_conditional_memcpy(t[0], in2[0], sizeof(t[0]), p1zero);
  constant_time_conditional_memcpy(t[1], in2[1], sizeof(t[1]), p1zero);
  constant_time_conditional_memcpy(t[2], fiat_p256_one, sizeof(t[2]), p1zero);
  OPENSSL_memcpy(out, t, sizeof(t));
}

static void fiat_p256_point_add_affine_conditional(fiat_p256_felem out[3],
                                                   const fiat_p256_felem in1[3],
                                                   const fiat_p256_felem in2[2],
                                                   size_t c) {
  crypto_word_t p1zero = fiat_p256_is_zero(in1[2]);
  crypto_word_t p2zero = constant_time_is_zero_w(c);
  fiat_p256_felem p_out[3];
  crypto_word_t doubling = fiat_p256_point_add_nz_nz_neq(p_out, in1, 1, in2);
  (void)doubling; assert(!(doubling & ~(p1zero | p2zero)));
  fiat_p256_felem t[3] = {{0}, {0}, {0}};
  constant_time_conditional_memxor(t,    p_out,        sizeof(t),   ~p1zero & ~p2zero);
  constant_time_conditional_memxor(t,    in1,          sizeof(t),   ~p1zero &  p2zero);
  constant_time_conditional_memxor(t[0], in2[0],       sizeof(t[0]), p1zero & ~p2zero);
  constant_time_conditional_memxor(t[1], in2[1],       sizeof(t[1]), p1zero & ~p2zero);
  constant_time_conditional_memxor(t[2], fiat_p256_one,sizeof(t[2]), p1zero & ~p2zero);
  OPENSSL_memcpy(out, t, sizeof(t));
}

// constant_time_table_select copies to |dst| from |src| the |i|th out of |n|
// |s|-byte elements, without leaking |i| through timing. Specialized versions
// |constant_time_table_select_64|, |constant_time_table_select_96| are faster.
inline
static void constant_time_table_select(uint8_t *dst, const uint8_t *src,
                                       size_t i, size_t n, size_t s) {
  assert(!buffers_alias(dst, s, src, n*s));
  if (buffers_alias(dst, s, src, n*s)) {
    __builtin_unreachable();
  }
  OPENSSL_memset(dst, 0, s);
#pragma clang loop unroll_count(4)
  for (size_t j = 0; j < n; j++) {
    constant_time_conditional_memxor(dst, &src[j*s], s, constant_time_eq_w(i, j));
  }
}

// constant_time_table_select_64 copies to |dst| from |src| the |i|th out of
// |n| 64-byte elements, without leaking |i| through timing.
__attribute__((always_inline))
static void constant_time_table_select_64(uint8_t *dst, const uint8_t *src,
                                          size_t i, size_t n) {
  static const size_t s = 64;
  uint8_t t[64] = {0};
#pragma clang loop unroll_count(8)
  for (size_t j = 0; j < n; j++) {
    constant_time_conditional_memxor(t, &src[j*s], s, constant_time_eq_w(i, j));
  }
  OPENSSL_memcpy(dst, t, s);
}

// constant_time_table_select_96 copies to |dst| from |src| the |i|th out of
// |n| 96-byte elements, without leaking |i| through timing.
__attribute__((always_inline))
static void constant_time_table_select_96(uint8_t *dst, const uint8_t *src,
                                          size_t i, size_t n) {
  static const size_t s = 96;
  uint8_t t[96] = {0};
#pragma clang loop unroll_count(4)
  for (size_t j = 0; j < n; j++) {
    constant_time_conditional_memxor(t, &src[j*s], s, constant_time_eq_w(i, j));
  }
  OPENSSL_memcpy(dst, t, s);
}

#include "./p256_table.h"

// fiat_p256_select_point_affine selects the |i|th point from a precomputation
// table and copies it to |dst|. If |n<=i|, the dstput is (0, 0).
__attribute__((always_inline))
static void fiat_p256_select_point_affine(
    fiat_p256_felem dst[2], const fiat_p256_felem src[/*n*/][2],
    size_t i, size_t n) {
  static_assert(sizeof(src[0]) == 64, "");
  constant_time_table_select_64((uint8_t*)dst, (uint8_t*)src, i, n);
}

// fiat_p256_select_point selects the |i|th point from a precomputation table
// and copies it to |dst|.
__attribute__((always_inline))
static void fiat_p256_select_point(fiat_p256_felem dst[3],
                                   const fiat_p256_felem src[/*n*/][3],
                                   size_t i, size_t n) {
  static_assert(sizeof(src[0]) == 96, "");
  constant_time_table_select_96((uint8_t*)dst, (uint8_t*)src, i, n);
}

__attribute__((noinline))
static void fiat_p256_select_point_16(fiat_p256_felem dst[3],
                                      const fiat_p256_felem src[16][3],
                                      size_t i) {
  fiat_p256_select_point(dst, src, i, 16);
}

// bit returns the |i|th bit in |in|.
static crypto_word_t bit(const uint8_t *in, int i) {
  if (i < 0 || i >= 256) {
    return 0;
  }
  return (in[i >> 3] >> (i & 7)) & 1;
}

// OPENSSL EC_METHOD FUNCTIONS

// Takes the Jacobian coordinates (X, Y, Z) of a point and returns (X', Y') =
// (X/Z^2, Y/Z^3).
static int ec_GFp_nistp256_point_get_affine_coordinates(
    const EC_GROUP *group, const EC_JACOBIAN *point, EC_FELEM *x_out,
    EC_FELEM *y_out) {
  if (constant_time_declassify_int(
          ec_GFp_simple_is_at_infinity(group, point))) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    return 0;
  }

  fiat_p256_felem z1, z2;
  fiat_p256_from_generic(z1, &point->Z);
  fiat_p256_inv_square(z2, z1);

  if (x_out != NULL) {
    fiat_p256_felem x;
    fiat_p256_from_generic(x, &point->X);
    fiat_p256_mul(x, x, z2);
    fiat_p256_to_generic(x_out, x);
  }

  if (y_out != NULL) {
    fiat_p256_felem y;
    fiat_p256_from_generic(y, &point->Y);
    fiat_p256_square(z2, z2);  // z^-4
    fiat_p256_mul(y, y, z1);   // y * z
    fiat_p256_mul(y, y, z2);   // y * z^-3
    fiat_p256_to_generic(y_out, y);
  }

  return 1;
}

static void p256_point_mul(fiat_p256_felem out[3], const fiat_p256_felem p[3],
                           const uint8_t s[32]) {
  fiat_p256_felem alignas(32) p_pre_comp[16][3];
  OPENSSL_memcpy(p_pre_comp[0], p, sizeof(p_pre_comp[0]));
  for (size_t j = 2; j <= 16; ++j) {
    if (j & 1) {
      fiat_p256_point_add(p_pre_comp[j-1], p_pre_comp[j-2], p_pre_comp[0]);
    } else {
      fiat_p256_point_double(p_pre_comp[j-1], p_pre_comp[(j-1) / 2]);
    }
  }

  fiat_p256_felem alignas(32) ret[3];
  int ret_is_zero = 1;

  for (size_t i = 51; i < 52; i--) {
    if (!ret_is_zero) {
      for (size_t k = 4; k < 5; k--) {
        fiat_p256_point_double(ret, ret);
      }
    }

    crypto_word_t bits = 0;
#pragma clang loop unroll(full)
    for (size_t k = 5; k < 6; k--) {
      bits |= bit(s, i*5-1 + k) << k;
    }
    crypto_word_t sign, digit;
    ec_GFp_nistp_recode_scalar_bits(&sign, &digit, bits);

    fiat_p256_felem alignas(32) t[3];
    fiat_p256_select_point_16(t, p_pre_comp, digit-1);
    fiat_p256_opp_conditional(t[1], sign);

    if (!ret_is_zero) {
      fiat_p256_point_add(ret, ret, t);
    } else {
      OPENSSL_memcpy(ret, t, sizeof(ret));
      ret_is_zero = 0;
    }
  }

  OPENSSL_memcpy(out, ret, sizeof(ret));
}

static int ec_GFp_nistp256_cmp_x_coordinate(const EC_GROUP *group,
                                            const EC_JACOBIAN *p,
                                            const EC_SCALAR *r) {
  if (ec_GFp_simple_is_at_infinity(group, p)) {
    return 0;
  }

  // We wish to compare X/Z^2 with r. This is equivalent to comparing X with
  // r*Z^2. Note that X and Z are represented in Montgomery form, while r is
  // not.
  fiat_p256_felem Z2_mont;
  fiat_p256_from_generic(Z2_mont, &p->Z);
  fiat_p256_mul(Z2_mont, Z2_mont, Z2_mont);

  fiat_p256_felem r_Z2;
  fiat_p256_from_words(r_Z2, r->words);  // r < order < p, so this is valid.
  fiat_p256_mul(r_Z2, r_Z2, Z2_mont);

  fiat_p256_felem X;
  fiat_p256_from_generic(X, &p->X);
  fiat_p256_from_montgomery(X, X);

  if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
    return 1;
  }

  // During signing the x coefficient is reduced modulo the group order.
  // Therefore there is a small possibility, less than 1/2^128, that group_order
  // < p.x < P. in that case we need not only to compare against |r| but also to
  // compare against r+group_order.
  assert(group->field.N.width == group->order.N.width);
  EC_FELEM tmp;
  BN_ULONG carry =
      bn_add_words(tmp.words, r->words, group->order.N.d, group->field.N.width);
  if (carry == 0 &&
      bn_less_than_words(tmp.words, group->field.N.d, group->field.N.width)) {
    fiat_p256_from_generic(r_Z2, &tmp);
    fiat_p256_mul(r_Z2, r_Z2, Z2_mont);
    if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
      return 1;
    }
  }

  return 0;
}

static void ec_GFp_nistp256_point_mul_public(const EC_GROUP *group,
                                             EC_JACOBIAN *r,
                                             const EC_SCALAR *gs,
                                             const EC_JACOBIAN *p,
                                             const EC_SCALAR *ps) {
  const uint8_t* g_scalar = (uint8_t*)gs->words;
  int8_t p_wNAF[257] = {0};

  fiat_p256_felem alignas(32) p_pre_comp[1 << (4 - 1)][3];
  fiat_p256_from_generic(p_pre_comp[0][2], &p->Z);
  if (!fiat_p256_is_zero(p_pre_comp[0][2])) {
    ec_compute_wNAF(group, p_wNAF, ps, 256, 4);
    // Precompute multiples of |p|. p_pre_comp[i] is (2*i+1) * |p|.
    fiat_p256_from_generic(p_pre_comp[0][0], &p->X);
    fiat_p256_from_generic(p_pre_comp[0][1], &p->Y);
    fiat_p256_felem alignas(32) p2[3];
    fiat_p256_point_double(p2, p_pre_comp[0]);
    for (size_t i = 1; i < OPENSSL_ARRAY_SIZE(p_pre_comp); i++) {
      fiat_p256_point_add_nz_nz(p_pre_comp[i], p_pre_comp[i - 1], p2);
    }
  }

  fiat_p256_felem alignas(32) ret[3];
  int ret_is_zero = 1;  // Save some point operations.
  for (int i = 256; i >= 0; i--) {
    if (!ret_is_zero) {
      fiat_p256_point_double(ret, ret);
    }

    if (i <= 31) {
#pragma clang loop unroll(full)
      for (size_t j = 1; j<2; j--) {
        crypto_word_t bits = 0;
#pragma clang loop unroll(full)
        for (size_t k = 3; k<4; k--) {
          bits |= bit(g_scalar, i + j*32 + k*64) << k;
        }
        if (bits != 0) {
          if (!ret_is_zero) {
            fiat_p256_point_add_affine_nz(ret, ret, fiat_p256_g_pre_comp[j][bits-1]);
          } else {
            OPENSSL_memcpy(ret, fiat_p256_g_pre_comp[j][bits-1], sizeof(fiat_p256_g_pre_comp[j][bits-1]));
            OPENSSL_memcpy(ret[2], fiat_p256_one, sizeof(ret[2]));
            ret_is_zero = 0;
          }
        }
      }
    }

    int digit = p_wNAF[i];
    if (digit != 0) {
      assert(digit & 1);
      size_t idx = (size_t)(digit < 0 ? (-digit) >> 1 : digit >> 1);
      fiat_p256_felem t[3];
      OPENSSL_memcpy(t, p_pre_comp[idx], sizeof(t));
      if (digit < 0) {
        fiat_p256_opp(t[1], t[1]);
      }
      if (!ret_is_zero) {
        fiat_p256_point_add_nz(ret, ret, t);
      } else {
        OPENSSL_memcpy(ret, t, sizeof(ret));
        ret_is_zero = 0;
      }
    }
  }

  fiat_p256_to_generic(&r->X, ret[0]);
  fiat_p256_to_generic(&r->Y, ret[1]);
  fiat_p256_to_generic(&r->Z, ret[2]);
}

#if defined(OPENSSL_SMALL)

__attribute__((noinline))
static void fiat_p256_select_point_affine_15(
    fiat_p256_felem dst[2], const fiat_p256_felem src[/*n*/][2],
    size_t i) {
  fiat_p256_select_point_affine(dst, src, i, 15);
}

static void p256_point_mul_base(fiat_p256_felem ret[3], const uint8_t s[32]) {
  int ret_is_zero = 1;  // Save two point operations in the first round.
  for (size_t i = 31; i < 32; i--) {
    if (!ret_is_zero) {
      fiat_p256_point_double(ret, ret);
    }
#pragma clang loop unroll(full)
    for (size_t j = 1; j < 2; j--) {
      crypto_word_t bits = 0;
#pragma clang loop unroll(full)
      for (size_t k = 3; k < 4; k--) {
        bits |= bit(s, i + 32 * j + 64 * k) << k;
      }
      fiat_p256_felem alignas(32) t[2];
      fiat_p256_select_point_affine_15(t, fiat_p256_g_pre_comp[j], bits-1);

      if (!ret_is_zero) {
        fiat_p256_point_add_affine_conditional(ret, ret, t, bits);
      } else {
        OPENSSL_memcpy(ret, t, sizeof(t));
        fiat_p256_conditional_zero_or_one(ret[2], bits);
        ret_is_zero = 0;
      }
    }
  }
}

#else // defined(OPENSSL_SMALL)

// p256-nistz.c

/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2014, Intel Corporation. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Shay Gueron (1, 2), and Vlad Krasnov (1)
 * (1) Intel Corporation, Israel Development Center, Haifa, Israel
 * (2) University of Haifa, Israel
 *
 * Reference:
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with
 *                          256 Bit Primes"
 */

// Precomputed tables for the default generator
typedef fiat_p256_felem _p256_affine_table_point[2];
typedef _p256_affine_table_point PRECOMP256_ROW[64];
#include "p256-nistz-table.h"

__attribute__((noinline))
static void fiat_p256_select_point_affine_16(fiat_p256_felem dst[2],
                                             const fiat_p256_felem src[16][2],
                                             size_t i) {
  fiat_p256_select_point_affine(dst, src, i, 16);
}

__attribute__((noinline))
static void fiat_p256_select_point_affine_64(fiat_p256_felem dst[2],
                                             const fiat_p256_felem src[64][2],
                                             size_t i) {
  fiat_p256_select_point_affine(dst, src, i, 64);
}

// See |ec_GFp_nistp_recode_scalar_bits| in util.c for details
static crypto_word_t booth_recode_w7(crypto_word_t in) {
  crypto_word_t s, d;
  s = ~((in >> 7) - 1);
  d = (1 << 8) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);
  return (d << 1) + (s & 1);
}

static void p256_point_mul_base(fiat_p256_felem ret[3], const uint8_t s[32]) {
  int ret_is_zero = 1;
  for (size_t i = 36; i < 37; i--) {
    crypto_word_t wvalue;
    if (!i) {
      wvalue = booth_recode_w7((s[0] << 1) & ((1<<(7+1))-1));
    } else {
      size_t bi = ((int)i*7 - 1) / 8;
      wvalue = (crypto_word_t)s[bi] | (bi < 31 ? s[bi + 1] : 0) << 8;
      wvalue = booth_recode_w7((wvalue >> (((int)i*7 - 1) % 8)) & ((1<<(7+1))-1));
    }
    alignas(32) fiat_p256_felem t[2];
    if (i==36) {
      fiat_p256_select_point_affine_16(t, ecp_nistz256_precomputed[i], (wvalue>>1)-1);
    } else {
      fiat_p256_select_point_affine_64(t, ecp_nistz256_precomputed[i], (wvalue>>1)-1);
    }
    fiat_p256_opp_conditional(t[1], wvalue & 1);

    if (!ret_is_zero) {
      fiat_p256_point_add_affine_conditional(ret, ret, t, wvalue>>1);
    } else {
      OPENSSL_memcpy(ret, t, sizeof(t));
      fiat_p256_conditional_zero_or_one(ret[2], wvalue >> 1);
      ret_is_zero = 0;
    }
  }
}

#endif // !OPENSSL_SMALL

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64))

#include "p256-nistz.h"

static inline void nistz_p256ord_mul(BN_ULONG res[P256_LIMBS],
                               const BN_ULONG a[P256_LIMBS],
                               const BN_ULONG b[P256_LIMBS]) {
#if defined(OPENSSL_X86_64)
  if (CRYPTO_is_ADX_capable()) {
    return ecp_nistz256_ord_mul_montx(res, a, b);
  }
#endif
  return ecp_nistz256_ord_mul_mont(res, a, b);
}

static inline void nistz_p256ord_sqr(BN_ULONG res[P256_LIMBS],
                                     const BN_ULONG a[P256_LIMBS],
                                     BN_ULONG rep) {
#if defined(OPENSSL_X86_64)
  if (CRYPTO_is_ADX_capable()) {
    return ecp_nistz256_ord_sqr_montx(res, a, rep);
  }
#endif
  return ecp_nistz256_ord_sqr_mont(res, a, rep);
}

static void ecp_nistz256_inv0_mod_ord(const EC_GROUP *group, EC_SCALAR *out,
                                      const EC_SCALAR *in) {
  // table[i] stores a power of |in| corresponding to the matching enum value.
  enum {
    // The following indices specify the power in binary.
    i_1 = 0,
    i_10,
    i_11,
    i_101,
    i_111,
    i_1010,
    i_1111,
    i_10101,
    i_101010,
    i_101111,
    // The following indices specify 2^N-1, or N ones in a row.
    i_x6,
    i_x8,
    i_x16,
    i_x32
  };
  BN_ULONG table[15][P256_LIMBS];

  // https://briansmith.org/ecc-inversion-addition-chains-01#p256_scalar_inversion
  //
  // Even though this code path spares 12 squarings, 4.5%, and 13
  // multiplications, 25%, the overall sign operation is not that much faster,
  // not more that 2%. Most of the performance of this function comes from the
  // scalar operations.

  // Pre-calculate powers.
  OPENSSL_memcpy(table[i_1], in->words, P256_LIMBS * sizeof(BN_ULONG));

  nistz_p256ord_sqr(table[i_10], table[i_1], 1);

  nistz_p256ord_mul(table[i_11], table[i_1], table[i_10]);

  nistz_p256ord_mul(table[i_101], table[i_11], table[i_10]);

  nistz_p256ord_mul(table[i_111], table[i_101], table[i_10]);

  nistz_p256ord_sqr(table[i_1010], table[i_101], 1);

  nistz_p256ord_mul(table[i_1111], table[i_1010], table[i_101]);

  nistz_p256ord_sqr(table[i_10101], table[i_1010], 1);
  nistz_p256ord_mul(table[i_10101], table[i_10101], table[i_1]);

  nistz_p256ord_sqr(table[i_101010], table[i_10101], 1);

  nistz_p256ord_mul(table[i_101111], table[i_101010], table[i_101]);

  nistz_p256ord_mul(table[i_x6], table[i_101010], table[i_10101]);

  nistz_p256ord_sqr(table[i_x8], table[i_x6], 2);
  nistz_p256ord_mul(table[i_x8], table[i_x8], table[i_11]);

  nistz_p256ord_sqr(table[i_x16], table[i_x8], 8);
  nistz_p256ord_mul(table[i_x16], table[i_x16], table[i_x8]);

  nistz_p256ord_sqr(table[i_x32], table[i_x16], 16);
  nistz_p256ord_mul(table[i_x32], table[i_x32], table[i_x16]);

  // Compute |in| raised to the order-2.
  nistz_p256ord_sqr(out->words, table[i_x32], 64);
  nistz_p256ord_mul(out->words, out->words, table[i_x32]);
  static const struct {
    uint8_t p, i;
  } kChain[27] = {{32, i_x32},    {6, i_101111}, {5, i_111},    {4, i_11},
                  {5, i_1111},    {5, i_10101},  {4, i_101},    {3, i_101},
                  {3, i_101},     {5, i_111},    {9, i_101111}, {6, i_1111},
                  {2, i_1},       {5, i_1},      {6, i_1111},   {5, i_111},
                  {4, i_111},     {5, i_111},    {5, i_101},    {3, i_11},
                  {10, i_101111}, {2, i_11},     {5, i_11},     {5, i_11},
                  {3, i_1},       {7, i_10101},  {6, i_1111}};
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kChain); i++) {
    nistz_p256ord_sqr(out->words, out->words, kChain[i].p);
    nistz_p256ord_mul(out->words, out->words, table[kChain[i].i]);
  }
}

static int ecp_nistz256_scalar_to_montgomery_inv_vartime(const EC_GROUP *group,
                                                 EC_SCALAR *out,
                                                 const EC_SCALAR *in) {
#if defined(OPENSSL_X86_64)
  if (!CRYPTO_is_AVX_capable()) {
    // No AVX support; fallback to generic code.
    return ec_simple_scalar_to_montgomery_inv_vartime(group, out, in);
  }
#endif

  assert(group->order.N.width == P256_LIMBS);
  if (!beeu_mod_inverse_vartime(out->words, in->words, group->order.N.d)) {
    return 0;
  }

  // The result should be returned in the Montgomery domain.
  ec_scalar_to_montgomery(group, out, out);
  return 1;
}

#endif /* !defined(OPENSSL_NO_ASM) && \
          (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)) */

static void ec_GFp_nistp256_point_mul(const EC_GROUP *group, EC_JACOBIAN *r,
                                      const EC_JACOBIAN *p,
                                      const EC_SCALAR *scalar) {
  fiat_p256_felem t[3];
  fiat_p256_from_generic(t[0], &p->X);
  fiat_p256_from_generic(t[1], &p->Y);
  fiat_p256_from_generic(t[2], &p->Z);
  p256_point_mul(t, t, (uint8_t*)scalar->words);

  fiat_p256_to_generic(&r->X, t[0]);
  fiat_p256_to_generic(&r->Y, t[1]);
  fiat_p256_to_generic(&r->Z, t[2]);
}

static void ec_GFp_nistp256_point_mul_base(const EC_GROUP *group,
                                           EC_JACOBIAN *r, const EC_SCALAR *s) {
  fiat_p256_felem alignas(32) ret[3];
  p256_point_mul_base(ret, (uint8_t *)s->words);
  fiat_p256_to_generic(&r->X, ret[0]);
  fiat_p256_to_generic(&r->Y, ret[1]);
  fiat_p256_to_generic(&r->Z, ret[2]);
}

static void ec_GFp_nistp256_add(const EC_GROUP *group, EC_JACOBIAN *r,
                                const EC_JACOBIAN *a, const EC_JACOBIAN *b) {
  fiat_p256_felem p[3], q[3];
  fiat_p256_from_generic(p[0], &a->X);
  fiat_p256_from_generic(p[1], &a->Y);
  fiat_p256_from_generic(p[2], &a->Z);
  fiat_p256_from_generic(q[0], &b->X);
  fiat_p256_from_generic(q[1], &b->Y);
  fiat_p256_from_generic(q[2], &b->Z);
  crypto_word_t nontrivial_doubling = fiat_p256_point_add_nnteq(p, p, q);
  if (constant_time_declassify_w(nontrivial_doubling)) {
    fiat_p256_point_double(p, q);
  }
  fiat_p256_to_generic(&r->X, p[0]);
  fiat_p256_to_generic(&r->Y, p[1]);
  fiat_p256_to_generic(&r->Z, p[2]);
}

static void ec_GFp_nistp256_dbl(const EC_GROUP *group, EC_JACOBIAN *r,
                                const EC_JACOBIAN *a) {
  fiat_p256_felem p[3];
  fiat_p256_from_generic(p[0], &a->X);
  fiat_p256_from_generic(p[1], &a->Y);
  fiat_p256_from_generic(p[2], &a->Z);
  fiat_p256_point_double(p, p);
  fiat_p256_to_generic(&r->X, p[0]);
  fiat_p256_to_generic(&r->Y, p[1]);
  fiat_p256_to_generic(&r->Z, p[2]);
}

DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_nistp256_method) {
  out->point_get_affine_coordinates =
      ec_GFp_nistp256_point_get_affine_coordinates;
  out->add = ec_GFp_nistp256_add;
  out->dbl = ec_GFp_nistp256_dbl;
  out->mul = ec_GFp_nistp256_point_mul;
  out->mul_base = ec_GFp_nistp256_point_mul_base;
  out->mul_public = ec_GFp_nistp256_point_mul_public;
  out->felem_mul = ec_GFp_mont_felem_mul;
  out->felem_sqr = ec_GFp_mont_felem_sqr;
  out->felem_to_bytes = ec_GFp_mont_felem_to_bytes;
  out->felem_from_bytes = ec_GFp_mont_felem_from_bytes;
  out->felem_reduce = ec_GFp_mont_felem_reduce;
  // TODO(davidben): This should use the specialized field arithmetic
  // implementation, rather than the generic one.
  out->felem_exp = ec_GFp_mont_felem_exp;
#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64))
  out->scalar_inv0_montgomery = ecp_nistz256_inv0_mod_ord;
  out->scalar_to_montgomery_inv_vartime =
      ecp_nistz256_scalar_to_montgomery_inv_vartime;
#else
  out->scalar_inv0_montgomery = ec_simple_scalar_inv0_montgomery;
  out->scalar_to_montgomery_inv_vartime =
      ec_simple_scalar_to_montgomery_inv_vartime;
#endif
  out->cmp_x_coordinate = ec_GFp_nistp256_cmp_x_coordinate;
}
