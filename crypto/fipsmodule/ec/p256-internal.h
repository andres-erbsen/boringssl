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

#ifndef OPENSSL_HEADER_EC_P256_X86_64_H
#define OPENSSL_HEADER_EC_P256_X86_64_H

#include <openssl/base.h>

#include <openssl/bn.h>

#include "../../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define P256_LIMBS (32 / sizeof(crypto_word_t))
typedef crypto_word_t fiat_p256_felem[P256_LIMBS];

void fiat_p256_opp(fiat_p256_felem out, const fiat_p256_felem in1);
void fiat_p256_mul(fiat_p256_felem out, const fiat_p256_felem in1, const fiat_p256_felem in2);
void fiat_p256_square(fiat_p256_felem out, const fiat_p256_felem in1);
void fiat_p256_from_montgomery(fiat_p256_felem out, const fiat_p256_felem in1);

void p256_point_add(uintptr_t out, uintptr_t in1, uintptr_t in2);
void p256_point_add_affine_conditional(uintptr_t ret, uintptr_t p, uintptr_t q_aff, uintptr_t c);
void p256_point_double(uintptr_t out, uintptr_t in1);

// P-256 scalar operations.
//
// The following functions compute modulo N, where N is the order of P-256. They
// take fully-reduced inputs and give fully-reduced outputs.

// ecp_nistz256_ord_mul_mont sets |res| to |a| * |b| where inputs and outputs
// are in Montgomery form. That is, |res| is |a| * |b| * 2^-256 mod N.
void ecp_nistz256_ord_mul_mont(BN_ULONG res[4], const BN_ULONG a[4],
                               const BN_ULONG b[4]);
void ecp_nistz256_ord_mul_montx(BN_ULONG res[4], const BN_ULONG a[4],
                                const BN_ULONG b[4]);

// ecp_nistz256_ord_sqr_mont sets |res| to |a|^(2*|rep|) where inputs and
// outputs are in Montgomery form. That is, |res| is
// (|a| * 2^-256)^(2*|rep|) * 2^256 mod N.
void ecp_nistz256_ord_sqr_mont(BN_ULONG res[4], const BN_ULONG a[4],
                               BN_ULONG rep);
void ecp_nistz256_ord_sqr_montx(BN_ULONG res[4], const BN_ULONG a[4],
                                BN_ULONG rep);

// beeu_mod_inverse_vartime sets out = a^-1 mod p using a Euclidean algorithm.
// Assumption: 0 < a < p < 2^(256) and p is odd.
int beeu_mod_inverse_vartime(BN_ULONG out[4], const BN_ULONG a[4],
                             const BN_ULONG p[4]);

#if defined(__cplusplus)
}  // extern C++
#endif

#endif  // OPENSSL_HEADER_EC_P256_X86_64_H
