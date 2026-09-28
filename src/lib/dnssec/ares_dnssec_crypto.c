/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_private.h"
#include "ares_dnssec.h"
#include "ares_dnssec_int.h"

/* Cryptographic operations for the DNSSEC validator.
 *
 * c-ares has no cryptography of its own: signatures are verified and hashes
 * calculated by the functions the application provides.  What is acceptable
 * is decided here, before they are called: the signature algorithms and
 * digest types known, the sizes of RSA keys, and the lengths of keys and
 * signatures of the other algorithms.
 *
 * Signature algorithms (RFC 8624):
 *   5  RSASHA1             RFC 3110
 *   7  RSASHA1-NSEC3-SHA1  RFC 5155
 *   8  RSASHA256           RFC 5702
 *   10 RSASHA512           RFC 5702
 *   13 ECDSAP256SHA256     RFC 6605
 *   14 ECDSAP384SHA384     RFC 6605
 *   15 ED25519             RFC 8080
 *   16 ED448               RFC 8080
 * Digest types: 1 SHA-1, 2 SHA-256, 4 SHA-384. */

/* RSA modulus size limits in bits: RFC 3110 and RFC 5702 section 2.1 allow
 * 512 to 4096 bits for RSASHA1 and RSASHA256, RFC 5702 section 2.2 1024 to
 * 4096 bits for RSASHA512 */
#define DNSSEC_RSA_MIN_BITS    512
#define DNSSEC_RSA512_MIN_BITS 1024
#define DNSSEC_RSA_MAX_BITS    4096
/* Most octets in an RSA public exponent.  RFC 3110 allows exponents up to
 * 4096 bits, but a large exponent makes verifying as slow as signing.  Real
 * keys use 3 or 65537. */
#define DNSSEC_RSA_MAX_EXPLEN 8

ares_bool_t ares_dnssec_crypto_valid(const ares_dnssec_crypto_t *crypto)
{
  return (crypto != NULL && crypto->alg_supported != NULL &&
          crypto->verify != NULL && crypto->digest_supported != NULL &&
          crypto->digest != NULL)
           ? ARES_TRUE
           : ARES_FALSE;
}

/* The length of the digest of a digest type, 0 for an unknown type */
static size_t digest_len(unsigned char dtype)
{
  switch (dtype) {
    case DNSSEC_DIGEST_SHA1:
      return 20;
    case DNSSEC_DIGEST_SHA256:
      return 32;
    case DNSSEC_DIGEST_SHA384:
      return 48;
    default:
      return 0;
  }
}

ares_bool_t ares_dnssec_alg_supported(const ares_dnssec_crypto_t *crypto,
                                      unsigned char               alg)
{
  switch (alg) {
    case DNSSEC_ALG_RSASHA1:
    case DNSSEC_ALG_RSASHA1_NSEC3:
    case DNSSEC_ALG_RSASHA256:
    case DNSSEC_ALG_RSASHA512:
    case DNSSEC_ALG_ECDSAP256SHA256:
    case DNSSEC_ALG_ECDSAP384SHA384:
    case DNSSEC_ALG_ED25519:
    case DNSSEC_ALG_ED448:
      return crypto->alg_supported(alg, crypto->user_data) ? ARES_TRUE
                                                           : ARES_FALSE;
    default:
      return ARES_FALSE;
  }
}

ares_bool_t ares_dnssec_digest_supported(const ares_dnssec_crypto_t *crypto,
                                         unsigned char               dtype)
{
  if (digest_len(dtype) == 0) {
    return ARES_FALSE;
  }
  return crypto->digest_supported(dtype, crypto->user_data) ? ARES_TRUE
                                                            : ARES_FALSE;
}

/* Check an RSA public key (RFC 3110 section 2) and signature: the sizes of
 * the modulus and exponent, and that the signature is as long as the
 * modulus (RFC 8017 section 8.2.2) */
static ares_bool_t rsa_check(const unsigned char *key, size_t keylen,
                             size_t minbits, size_t siglen)
{
  const unsigned char *mod;
  size_t               explen;
  size_t               modlen;
  size_t               bits;
  unsigned char        top;

  if (keylen < 1) {
    return ARES_FALSE;
  }
  if (key[0] != 0) {
    explen = key[0];
    mod    = key + 1;
  } else {
    if (keylen < 3) {
      return ARES_FALSE;
    }
    explen = ((size_t)key[1] << 8) | key[2];
    mod    = key + 3;
  }
  if (explen == 0 || explen > DNSSEC_RSA_MAX_EXPLEN ||
      (size_t)(mod - key) + explen >= keylen) {
    return ARES_FALSE;
  }
  mod    += explen;
  modlen  = keylen - (size_t)(mod - key);
  /* the modulus has no leading zero octets */
  if (mod[0] == 0) {
    return ARES_FALSE;
  }
  bits = modlen * 8;
  for (top = mod[0]; !(top & 0x80); top = (unsigned char)(top << 1)) {
    bits--;
  }
  if (bits < minbits || bits > DNSSEC_RSA_MAX_BITS) {
    return ARES_FALSE;
  }
  return (siglen == modlen) ? ARES_TRUE : ARES_FALSE;
}

ares_status_t ares_dnssec_verify(const ares_dnssec_crypto_t *crypto,
                                 unsigned char alg, const unsigned char *key,
                                 size_t keylen, const unsigned char *data,
                                 size_t datalen, const unsigned char *sig,
                                 size_t siglen)
{
  ares_bool_t   ok;
  ares_status_t status;

  if (!ares_dnssec_alg_supported(crypto, alg)) {
    return ARES_ENOTIMP;
  }

  switch (alg) {
    case DNSSEC_ALG_RSASHA1:
    case DNSSEC_ALG_RSASHA1_NSEC3:
    case DNSSEC_ALG_RSASHA256:
      ok = rsa_check(key, keylen, DNSSEC_RSA_MIN_BITS, siglen);
      break;
    case DNSSEC_ALG_RSASHA512:
      ok = rsa_check(key, keylen, DNSSEC_RSA512_MIN_BITS, siglen);
      break;
    /* RFC 6605 section 4: the point as x | y, the signature as r | s */
    case DNSSEC_ALG_ECDSAP256SHA256:
      ok = (keylen == 64 && siglen == 64) ? ARES_TRUE : ARES_FALSE;
      break;
    case DNSSEC_ALG_ECDSAP384SHA384:
      ok = (keylen == 96 && siglen == 96) ? ARES_TRUE : ARES_FALSE;
      break;
    /* RFC 8080 section 3 and 4 */
    case DNSSEC_ALG_ED25519:
      ok = (keylen == 32 && siglen == 64) ? ARES_TRUE : ARES_FALSE;
      break;
    case DNSSEC_ALG_ED448:
      ok = (keylen == 57 && siglen == 114) ? ARES_TRUE : ARES_FALSE;
      break;
    default:
      return ARES_ENOTIMP; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  if (!ok) {
    return ARES_EFORMERR;
  }

  status = crypto->verify(alg, key, keylen, data, datalen, sig, siglen,
                          crypto->user_data);
  switch (status) {
    case ARES_SUCCESS:
    case ARES_ENOMEM:
    case ARES_ENOTIMP:
      return status;
    default:
      /* anything else means the signature is not valid */
      return ARES_EBADRESP;
  }
}

/* Hash 'data' with the application's function, checking the length */
static ares_status_t digest_one(const ares_dnssec_crypto_t *crypto,
                                unsigned char dtype, const unsigned char *data,
                                size_t        datalen,
                                unsigned char out[DNSSEC_DIGEST_MAX])
{
  size_t        outlen = DNSSEC_DIGEST_MAX;
  ares_status_t status;

  status =
    crypto->digest(dtype, data, datalen, out, &outlen, crypto->user_data);
  if (status != ARES_SUCCESS) {
    return status;
  }
  return (outlen == digest_len(dtype)) ? ARES_SUCCESS : ARES_EFORMERR;
}

size_t ares_dnssec_digest(const ares_dnssec_crypto_t *crypto,
                          unsigned char dtype, const unsigned char *d1,
                          size_t l1, const unsigned char *d2, size_t l2,
                          unsigned char out[DNSSEC_DIGEST_MAX])
{
  ares_buf_t          *buf;
  const unsigned char *data;
  size_t               len    = 0;
  ares_status_t        status = ARES_ENOMEM;

  if (!ares_dnssec_digest_supported(crypto, dtype)) {
    return 0;
  }
  buf = ares_buf_create();
  if (buf == NULL) {
    return 0; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  if (ares_buf_append(buf, d1, l1) == ARES_SUCCESS &&
      (l2 == 0 || ares_buf_append(buf, d2, l2) == ARES_SUCCESS)) {
    data   = ares_buf_peek(buf, &len);
    status = digest_one(crypto, dtype, data, len, out);
  }
  ares_buf_destroy(buf);
  return (status == ARES_SUCCESS) ? digest_len(dtype) : 0;
}

ares_status_t ares_dnssec_nsec3_hash(const ares_dnssec_crypto_t *crypto,
                                     const unsigned char *name, size_t namelen,
                                     const unsigned char *salt, size_t saltlen,
                                     unsigned short iterations,
                                     unsigned char  out[DNSSEC_NSEC3_HASHLEN])
{
  /* the name or the previous hash, followed by the salt */
  unsigned char input[DNSSEC_NAME_MAX + 255];
  unsigned char digest[DNSSEC_DIGEST_MAX];
  unsigned int  i;
  ares_status_t status;

  if (namelen > DNSSEC_NAME_MAX || saltlen > 255) {
    return ARES_EFORMERR;
  }
  if (!ares_dnssec_digest_supported(crypto, DNSSEC_DIGEST_SHA1)) {
    return ARES_ENOTIMP;
  }

  /* IH(salt, x, 0) = H(x || salt)
     IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0 */
  memcpy(input, name, namelen);
  if (saltlen) {
    memcpy(input + namelen, salt, saltlen);
  }
  status =
    digest_one(crypto, DNSSEC_DIGEST_SHA1, input, namelen + saltlen, digest);
  for (i = 0; i < iterations && status == ARES_SUCCESS; i++) {
    memcpy(input, digest, DNSSEC_NSEC3_HASHLEN);
    if (saltlen) {
      memcpy(input + DNSSEC_NSEC3_HASHLEN, salt, saltlen);
    }
    status = digest_one(crypto, DNSSEC_DIGEST_SHA1, input,
                        DNSSEC_NSEC3_HASHLEN + saltlen, digest);
  }
  if (status != ARES_SUCCESS) {
    return status;
  }
  memcpy(out, digest, DNSSEC_NSEC3_HASHLEN);
  return ARES_SUCCESS;
}
