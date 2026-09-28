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

#ifndef ARES_DNSSEC_INT_H
#define ARES_DNSSEC_INT_H
#include "ares_private.h"

/* Internals shared by the dnssec*.c files. Everything here works on DNS
   wire format. Domain names are kept uncompressed in wire format ("\3www\7
   example\3com\0"), at most DNSSEC_NAME_MAX bytes. */


#define DNSSEC_NAME_MAX   255
#define DNSSEC_LABELS_MAX 127

#define DNSSEC_CLASS_IN 1

/* Resource record types */
#define DNSSEC_TYPE_A      1
#define DNSSEC_TYPE_NS     2
#define DNSSEC_TYPE_CNAME  5
#define DNSSEC_TYPE_SOA    6
#define DNSSEC_TYPE_AAAA   28
#define DNSSEC_TYPE_DNAME  39
#define DNSSEC_TYPE_DS     43
#define DNSSEC_TYPE_RRSIG  46
#define DNSSEC_TYPE_NSEC   47
#define DNSSEC_TYPE_DNSKEY 48
#define DNSSEC_TYPE_NSEC3  50
#define DNSSEC_TYPE_TLSA   52
#define DNSSEC_TYPE_SVCB   64
#define DNSSEC_TYPE_HTTPS  65
#define DNSSEC_TYPE_MD     3
#define DNSSEC_TYPE_MF     4
#define DNSSEC_TYPE_MB     7
#define DNSSEC_TYPE_MG     8
#define DNSSEC_TYPE_MR     9
#define DNSSEC_TYPE_PTR    12
#define DNSSEC_TYPE_MINFO  14
#define DNSSEC_TYPE_MX     15
#define DNSSEC_TYPE_RP     17
#define DNSSEC_TYPE_AFSDB  18
#define DNSSEC_TYPE_RT     21
#define DNSSEC_TYPE_SIG    24
#define DNSSEC_TYPE_PX     26
#define DNSSEC_TYPE_NXT    30
#define DNSSEC_TYPE_SRV    33
#define DNSSEC_TYPE_NAPTR  35
#define DNSSEC_TYPE_KX     36
#define DNSSEC_TYPE_A6     38
#define DNSSEC_TYPE_OPT    41
#define DNSSEC_TYPE_NXNAME 128 /* RFC 9824 */

/* DNSKEY flags, RFC 4034 section 2.1.1 and RFC 5011 section 3 */
#define DNSSEC_DNSKEY_ZONE   0x0100
#define DNSSEC_DNSKEY_REVOKE 0x0080
#define DNSSEC_DNSKEY_SEP    0x0001

/* NSEC3 */
#define DNSSEC_NSEC3_SHA1    1
#define DNSSEC_NSEC3_OPTOUT  0x01
#define DNSSEC_NSEC3_HASHLEN 20

/* Algorithm numbers, RFC 8624 / RFC 9904 */
#define DNSSEC_ALG_RSASHA1         5
#define DNSSEC_ALG_RSASHA1_NSEC3   7
#define DNSSEC_ALG_RSASHA256       8
#define DNSSEC_ALG_RSASHA512       10
#define DNSSEC_ALG_ECDSAP256SHA256 13
#define DNSSEC_ALG_ECDSAP384SHA384 14
#define DNSSEC_ALG_ED25519         15
#define DNSSEC_ALG_ED448           16

/* DS digest types */
#define DNSSEC_DIGEST_SHA1   1
#define DNSSEC_DIGEST_SHA256 2
#define DNSSEC_DIGEST_SHA384 4
#define DNSSEC_DIGEST_MAX    48

/* Message sections */
#define DNSSEC_SECT_ANSWER    1
#define DNSSEC_SECT_AUTHORITY 2

/* rcodes */
#define DNSSEC_RCODE_NOERROR  0
#define DNSSEC_RCODE_NXDOMAIN 3

/* One resource record in a parsed message */
struct dnssec_rr {
  size_t         owner; /* offset of the uncompressed owner in msg->names */
  size_t         rdata; /* offset of the RDATA in msg->buf */
  unsigned int   ttl;
  unsigned short type;
  unsigned short rclass;
  unsigned short rdlen;
  unsigned char  section;
  /* cached validation result of the RRset this record starts */
  unsigned char  vstat;   /* status, 0 when not known */
  unsigned char  vlabels; /* RRSIG Labels value of the validating signature */
  unsigned char  vsigner; /* number of labels in the signer name */
  unsigned int   vttl;    /* TTL the RRset can be used for */
};

/* A parsed DNS response. Only the question, answer and authority sections
   are parsed, the validator has no use for the additional section. */
struct dnssec_msg {
  unsigned char    *buf;
  size_t            len;
  unsigned char    *names; /* owner names, uncompressed */
  struct dnssec_rr *rrs;
  size_t            nrrs;
  unsigned char     qname[DNSSEC_NAME_MAX];
  unsigned short    qtype;
  unsigned short    qclass;
  size_t            size; /* memory used, roughly */
  unsigned short    flags;
  unsigned char     rcode;
};

/*! Parse a response message.
 *
 *  \param[in]  buf   The message
 *  \param[in]  len   Length of the message
 *  \param[out] pmsg  The parsed message, which has a copy of 'buf'
 *  \return ARES_SUCCESS, ARES_EBADRESP for a malformed or unusable message,
 *          or ARES_ENOMEM
 */
ares_status_t ares_dnssec_msg_parse(const unsigned char *buf, size_t len,
                                    struct dnssec_msg **pmsg);

/*! Free a parsed message.
 *
 *  \param[in] msg  Message, may be NULL
 */
void ares_dnssec_msg_free(struct dnssec_msg *msg);

/*! The owner name of a record in a parsed message */
#define DNSSEC_RR_OWNER(m, rr) ((m)->names + (rr)->owner)
/*! The RDATA of a record in a parsed message */
#define DNSSEC_RR_RDATA(m, rr) ((m)->buf + (rr)->rdata)

/*! Read a domain name in wire format.
 *
 *  \param[in]     buf       A DNS message, or RDATA
 *  \param[in]     len       Length of 'buf'
 *  \param[in,out] offset    Where the name starts, advanced past the name as
 *                           stored
 *  \param[in]     compress  Follow compression pointers, only for a message
 *  \param[out]    out       The uncompressed name
 *  \return ARES_SUCCESS or ARES_EBADRESP
 */
ares_status_t ares_dnssec_read_name(const unsigned char *buf, size_t len,
                                    size_t *offset, ares_bool_t compress,
                                    unsigned char out[DNSSEC_NAME_MAX]);

/*! Length of a name in wire format, with the root label
 *
 *  \param[in] name  Name
 *  \return Length in octets
 */
size_t ares_dnssec_name_len(const unsigned char *name);

/*! Number of labels of a name, without the root label
 *
 *  \param[in] name  Name
 *  \return Number of labels
 */
unsigned int ares_dnssec_name_labels(const unsigned char *name);

/*! Number of labels of a name as in the RRSIG Labels field: without a
 *  leading '*' label (RFC 4034 section 3.1.3)
 *
 *  \param[in] name  Name
 *  \return Number of labels
 */
unsigned int ares_dnssec_name_sig_labels(const unsigned char *name);

/*! Compare two names, ignoring ASCII case
 *
 *  \param[in] a  Name
 *  \param[in] b  Name
 *  \return ARES_TRUE if equal
 */
ares_bool_t ares_dnssec_name_eq(const unsigned char *a, const unsigned char *b);

/*! Whether a name is at or below another
 *
 *  \param[in] name    Name
 *  \param[in] parent  Name of the possible parent
 *  \return ARES_TRUE if 'name' is 'parent' or below it
 */
ares_bool_t ares_dnssec_name_sub(const unsigned char *name,
                                 const unsigned char *parent);

/*! The last labels of a name
 *
 *  \param[in] name    Name
 *  \param[in] labels  Number of labels to keep, at most the number 'name' has
 *  \return Pointer into 'name'
 */
const unsigned char *ares_dnssec_name_suffix(const unsigned char *name,
                                             unsigned int         labels);

/*! Number of rightmost labels two names have in common
 *
 *  \param[in] a  Name
 *  \param[in] b  Name
 *  \return Number of labels
 */
unsigned int ares_dnssec_name_common(const unsigned char *a,
                                     const unsigned char *b);

/*! Compare two names in canonical DNS name order, RFC 4034 section 6.1
 *
 *  \param[in] a  Name
 *  \param[in] b  Name
 *  \return <0, 0 or >0
 */
int ares_dnssec_name_cmp(const unsigned char *a, const unsigned char *b);

/*! Copy a name in lowercase
 *
 *  \param[out] dest  Destination, may be 'name'
 *  \param[in]  name  Name
 */
void ares_dnssec_name_lower(unsigned char *dest, const unsigned char *name);

/*! Write a name in presentation format, with a trailing dot.  Octets that
 *  are not printable ASCII and the characters with a special meaning in
 *  zone files (RFC 1035 section 5.1) are escaped as \DDD.
 *
 *  \param[in]  name    Name
 *  \param[out] out     Buffer, the name is cut when it does not fit
 *  \param[in]  outlen  Size of 'out', ARES_DNSSEC_NAME_STRLEN fits all names
 */
void ares_dnssec_name_str(const unsigned char *name, char *out, size_t outlen);

/*! Parse a name in presentation format, with \X and \DDD escapes
 *
 *  \param[in]  str  Name, the trailing dot is optional
 *  \param[in]  len  Length of 'str'
 *  \param[out] out  The name in wire format
 *  \return ARES_SUCCESS or ARES_EFORMERR
 */
ares_status_t ares_dnssec_name_parse(const char *str, size_t len,
                                     unsigned char out[DNSSEC_NAME_MAX]);

/*! Append the canonical form (RFC 4034 section 6.2, RFC 6840 section 5.1)
 *  of the RDATA of a record
 *
 *  \param[in] m    Message
 *  \param[in] rr   Record in 'm'
 *  \param[in] out  Buffer to append to
 *  \return ARES_SUCCESS, ARES_EBADRESP for malformed RDATA, or ARES_ENOMEM
 */
ares_status_t ares_dnssec_rdata_canonical(const struct dnssec_msg *m,
                                          const struct dnssec_rr  *rr,
                                          ares_buf_t              *out);

/*! Whether a type is set in an NSEC or NSEC3 type bit map (RFC 4034
 *  section 4.1.2)
 *
 *  \param[in]  map   Type bit map
 *  \param[in]  len   Length of the map
 *  \param[in]  type  Type
 *  \param[out] pbad  Set to ARES_TRUE when the map is malformed
 *  \return ARES_TRUE if the type is set
 */
ares_bool_t ares_dnssec_bitmap_has(const unsigned char *map, size_t len,
                                   unsigned short type, ares_bool_t *pbad);

/*! Key tag of a DNSKEY record, RFC 4034 appendix B
 *
 *  \param[in] rdata  DNSKEY RDATA
 *  \param[in] rdlen  Length of the RDATA
 *  \return The key tag
 */
unsigned short ares_dnssec_keytag(const unsigned char *rdata, size_t rdlen);

/*! Decode a base32hex (RFC 4648 section 7) NSEC3 hash label
 *
 *  \param[in]  in      Label
 *  \param[in]  inlen   Length of the label
 *  \param[out] out     Decoded hash
 *  \param[in]  outlen  Size of 'out'
 *  \return The number of octets written, 0 on error
 */
size_t ares_dnssec_b32hex_decode(const unsigned char *in, size_t inlen,
                                 unsigned char *out, size_t outlen);

/*
 * Crypto, implemented in ares_dnssec_crypto.c with the functions the
 * application provides
 */

/*! Whether a signature algorithm is known and supported by the crypto
 *  functions
 *
 *  \param[in] crypto  Crypto functions
 *  \param[in] alg     DNSSEC algorithm number
 *  \return ARES_TRUE if supported
 */
ares_bool_t ares_dnssec_alg_supported(const ares_dnssec_crypto_t *crypto,
                                      unsigned char               alg);

/*! Whether a DS digest type is known and supported by the crypto functions
 *
 *  \param[in] crypto  Crypto functions
 *  \param[in] dtype   Digest type
 *  \return ARES_TRUE if supported
 */
ares_bool_t ares_dnssec_digest_supported(const ares_dnssec_crypto_t *crypto,
                                         unsigned char               dtype);

/*! Verify a signature.  The key and signature are checked (like the size
 *  of an RSA key) before the crypto functions are asked.
 *
 *  \param[in] crypto   Crypto functions
 *  \param[in] alg      DNSSEC algorithm number
 *  \param[in] key      Public key, as in a DNSKEY record
 *  \param[in] keylen   Length of the key
 *  \param[in] data     Signed data
 *  \param[in] datalen  Length of the data
 *  \param[in] sig      Signature, as in an RRSIG record
 *  \param[in] siglen   Length of the signature
 *  \return ARES_SUCCESS if the signature is valid, ARES_EBADRESP if it is
 *          not, ARES_ENOTIMP for an unsupported algorithm, ARES_EFORMERR for
 *          a malformed or unacceptable key or signature, or ARES_ENOMEM
 */
ares_status_t ares_dnssec_verify(const ares_dnssec_crypto_t *crypto,
                                 unsigned char alg, const unsigned char *key,
                                 size_t keylen, const unsigned char *data,
                                 size_t datalen, const unsigned char *sig,
                                 size_t siglen);

/*! Hash the concatenation of two buffers
 *
 *  \param[in]  crypto  Crypto functions
 *  \param[in]  dtype   DS digest type
 *  \param[in]  d1      First buffer
 *  \param[in]  l1      Length of the first buffer
 *  \param[in]  d2      Second buffer
 *  \param[in]  l2      Length of the second buffer, may be 0
 *  \param[out] out     The digest
 *  \return The digest length, 0 on error or for an unsupported type
 */
size_t ares_dnssec_digest(const ares_dnssec_crypto_t *crypto,
                          unsigned char dtype, const unsigned char *d1,
                          size_t l1, const unsigned char *d2, size_t l2,
                          unsigned char out[DNSSEC_DIGEST_MAX]);

/*! NSEC3 hash of a name, RFC 5155 section 5 (SHA-1 only)
 *
 *  \param[in]  crypto      Crypto functions
 *  \param[in]  name        Name in wire format, in lowercase
 *  \param[in]  namelen     Length of the name
 *  \param[in]  salt        Salt
 *  \param[in]  saltlen     Length of the salt
 *  \param[in]  iterations  Additional iterations
 *  \param[out] out         The hash
 *  \return ARES_SUCCESS, ARES_ENOTIMP without SHA-1, ARES_ENOMEM or another
 *          error from the crypto functions
 */
ares_status_t ares_dnssec_nsec3_hash(const ares_dnssec_crypto_t *crypto,
                                     const unsigned char *name, size_t namelen,
                                     const unsigned char *salt, size_t saltlen,
                                     unsigned short iterations,
                                     unsigned char  out[DNSSEC_NSEC3_HASHLEN]);

#endif /* ARES_DNSSEC_INT_H */
