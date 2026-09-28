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

#ifndef ARES_DNSSEC_H
#define ARES_DNSSEC_H

/* DNSSEC validation (RFC 4033, 4034, 4035, 5155, 6840 and friends).
 *
 * The validator itself does no I/O.  It is fed complete DNS response
 * messages and tells its user which queries it needs answers for, so the
 * same code can be driven by a channel (see ares_query_dnssec.c) or by a
 * test harness.
 *
 * All queries the validator asks for must be sent with the DO bit set (in
 * an EDNS0 OPT record) and the CD bit set (RFC 6840 section 5.9) to a
 * recursive resolver.  The resolver is not trusted: everything it returns is
 * validated from the configured trust anchors (by default, the DNS root
 * KSKs) down.
 *
 * Usage:
 *
 *   ares_dnssec_ctx_create(&crypto, &ctx);
 *   ares_dnssec_req_create(ctx, "_443._tcp.example.com", 52, &req);
 *   while (ares_dnssec_req_run(req, &done) == ARES_SUCCESS && !done) {
 *     while (ares_dnssec_ctx_next_query(ctx, name, sizeof(name), &qtype))
 *       ... send query, and when the response arrives:
 *       ares_dnssec_ctx_add_response(ctx, name, qtype, msg, msglen);
 *       ... or if the query failed:
 *       ares_dnssec_ctx_add_failure(ctx, name, qtype);
 *   }
 *   status = ares_dnssec_req_status(req);
 *
 * A context holds trust anchors, all responses and cached zone keys.  Many
 * requests can share one context and then also share the DNSKEY and DS
 * lookups.  A context is meant to live for the duration of a lookup, not
 * forever: it has fixed upper limits on the number of queries and the
 * amount of cryptographic work it does, as protection against resource
 * exhaustion attacks (like CVE-2023-50387, "KeyTrap").
 *
 * c-ares has no cryptography of its own: signatures are verified and hashes
 * calculated with functions the application provides. */

/*! The security status of an answer, RFC 4033 section 5 and RFC 4035
 *  section 4.3 */
typedef enum {
  /*! Validation did not complete: a lookup failed (timeout, SERVFAIL),
   *  there is no trust anchor covering the name, or a resource limit was
   *  hit.  The answer is neither proven secure nor proven insecure, and
   *  security decisions MUST treat it like ARES_DNSSEC_BOGUS. */
  ARES_DNSSEC_INDETERMINATE = 0,
  /*! A chain of trust from a trust anchor proves the answer (or its
   *  nonexistence) authentic. */
  ARES_DNSSEC_SECURE,
  /*! A chain of trust from a trust anchor proves that the answer comes from
   *  an unsigned part of the DNS (or one only signed with algorithms that
   *  are not accepted). */
  ARES_DNSSEC_INSECURE,
  /*! The answer should be signed but validation failed: missing or bad
   *  signatures, broken chain of trust, invalid denial of existence. */
  ARES_DNSSEC_BOGUS
} ares_dnssec_status_t;

/*! Maximum length of a domain name in presentation format, with all
 *  characters escaped as \DDD, plus a terminating zero */
#define ARES_DNSSEC_NAME_STRLEN 1010

/*! Context flag: accept the SHA-1 based signature algorithms RSASHA1 (5)
 *  and RSASHA1-NSEC3-SHA1 (7).  By default they are treated as unsupported,
 *  making zones signed only with them insecure, as RFC 9905 requires of
 *  validating resolver operators. */
#define ARES_DNSSEC_ALLOW_SHA1 (1 << 0)

/*! The most CNAME and DNAME links followed */
#define ARES_DNSSEC_MAX_CHAIN 12

/*! Cryptographic functions for the validator, see
 *  struct ares_dnssec_crypto_functions in ares.h for their contracts */
typedef struct {
  /*! Whether a signature algorithm (DNSSEC algorithm number) is supported */
  ares_bool_t (*alg_supported)(unsigned char algorithm, void *user_data);
  /*! Verify a signature made with a supported algorithm: ARES_SUCCESS if
   *  valid, ARES_EBADRESP if not, or ARES_ENOMEM */
  ares_status_t (*verify)(unsigned char algorithm, const unsigned char *key,
                          size_t key_len, const unsigned char *data,
                          size_t data_len, const unsigned char *sig,
                          size_t sig_len, void *user_data);
  /*! Whether a digest type (as in DS records) is supported */
  ares_bool_t (*digest_supported)(unsigned char digest_type, void *user_data);
  /*! Hash data with a supported digest type */
  ares_status_t (*digest)(unsigned char digest_type, const unsigned char *data,
                          size_t data_len, unsigned char *out, size_t *out_len,
                          void *user_data);
  /*! Passed to the functions */
  void *user_data;
} ares_dnssec_crypto_t;

/*! Whether all the crypto functions are set
 *
 *  \param[in] crypto  Crypto functions, may be NULL
 *
eturn ARES_TRUE if usable
 */
ares_bool_t ares_dnssec_crypto_valid(const ares_dnssec_crypto_t *crypto);

/*! Validation context: trust anchors, responses and validated zone keys */
typedef struct ares_dnssec_ctx ares_dnssec_ctx_t;
/*! Validation of the answer to one question */
typedef struct ares_dnssec_req ares_dnssec_req_t;

/*! Create a validation context, with the root zone trust anchors (the
 *  KSK-2017 and KSK-2024 key digests published by IANA) installed.
 *
 *  \param[in]  crypto  Crypto functions, which are copied
 *  \param[out] pctx    The new context
 *  \return ARES_SUCCESS, ARES_EFORMERR when a crypto function is missing, or
 *          ARES_ENOMEM
 */
ares_status_t ares_dnssec_ctx_create(const ares_dnssec_crypto_t *crypto,
                                     ares_dnssec_ctx_t         **pctx);

/*! Destroy a context.  All requests created on it must be destroyed first.
 *
 *  \param[in] ctx  Context, may be NULL
 */
void ares_dnssec_ctx_destroy(ares_dnssec_ctx_t *ctx);

/*! Remove all trust anchors, including the built-in ones.
 *
 *  \param[in] ctx  Context
 */
void ares_dnssec_ctx_clear_anchors(ares_dnssec_ctx_t *ctx);

/*! Add a trust anchor.  Set the trust anchors before creating requests:
 *  results are cached in the context.  A zone with trust anchors is trusted
 *  through them only, its parent is not asked.
 *
 *  \param[in] ctx  Context
 *  \param[in] rr   A DS or DNSKEY record in presentation (zone file) format,
 *                  like ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C...".
 *                  The TTL and class are optional, the owner is required.
 *  \return ARES_SUCCESS, ARES_EFORMERR for a malformed record or ARES_ENOMEM
 */
ares_status_t ares_dnssec_ctx_add_anchor(ares_dnssec_ctx_t *ctx,
                                         const char        *rr);

/*! Set ARES_DNSSEC_* flags
 *
 *  \param[in] ctx    Context
 *  \param[in] flags  Flags
 */
void ares_dnssec_ctx_set_flags(ares_dnssec_ctx_t *ctx, unsigned int flags);

/*! Validate signatures against a fixed time instead of the current time.
 *
 *  \param[in] ctx  Context
 *  \param[in] now  Seconds since the epoch, or 0 for the current time
 */
void ares_dnssec_ctx_set_time(ares_dnssec_ctx_t *ctx, time_t now);

/*! Get the next query the validator wants answered.  Each query is
 *  returned once.
 *
 *  \param[in]  ctx      Context
 *  \param[out] name     The query name in presentation format, with a
 *                       trailing dot
 *  \param[in]  namelen  Size of 'name', at least ARES_DNSSEC_NAME_STRLEN
 *  \param[out] qtype    The query type
 *  \return ARES_TRUE if there is a query to send, ARES_FALSE if there are
 *          no more queries to send at this time
 */
ares_bool_t ares_dnssec_ctx_next_query(ares_dnssec_ctx_t *ctx, char *name,
                                       size_t namelen, unsigned short *qtype);

/*! Add the response to a query returned by ares_dnssec_ctx_next_query().
 *  A message that cannot be parsed, or is not the response to the query, is
 *  kept as a failed lookup.
 *
 *  \param[in] ctx     Context
 *  \param[in] name    The query name
 *  \param[in] qtype   The query type
 *  \param[in] msg     The response message, which is copied
 *  \param[in] msglen  Length of the message
 *  \return ARES_SUCCESS when the response was stored, ARES_EFORMERR when
 *          no such query was asked for, or ARES_ENOMEM
 */
ares_status_t ares_dnssec_ctx_add_response(ares_dnssec_ctx_t   *ctx,
                                           const char          *name,
                                           unsigned short       qtype,
                                           const unsigned char *msg,
                                           size_t               msglen);

/*! Mark a query as failed, like for a timeout or a SERVFAIL response.
 *
 *  \param[in] ctx    Context
 *  \param[in] name   The query name
 *  \param[in] qtype  The query type
 *  \return ARES_SUCCESS, or ARES_EFORMERR when no such query was asked for
 */
ares_status_t ares_dnssec_ctx_add_failure(ares_dnssec_ctx_t *ctx,
                                          const char        *name,
                                          unsigned short     qtype);

/*! Number of queries asked for that have no response or failure yet.
 *
 *  \param[in] ctx  Context
 *  \return The number of queries
 */
size_t ares_dnssec_ctx_pending(const ares_dnssec_ctx_t *ctx);

/*! Create a request to validate the answer for a question (class IN).
 *
 *  \param[in]  ctx    Context
 *  \param[in]  name   Question name in presentation format
 *  \param[in]  qtype  Question type, not a meta type like ANY or OPT
 *  \param[out] preq   The new request
 *  \return ARES_SUCCESS, ARES_EFORMERR for a bad name or type, or ARES_ENOMEM
 */
ares_status_t ares_dnssec_req_create(ares_dnssec_ctx_t *ctx, const char *name,
                                     unsigned short      qtype,
                                     ares_dnssec_req_t **preq);

/*! Destroy a request.
 *
 *  \param[in] req  Request, may be NULL
 */
void ares_dnssec_req_destroy(ares_dnssec_req_t *req);

/*! Advance the validation with the responses available in the context.
 *
 *  \param[in]  req   Request
 *  \param[out] done  ARES_FALSE when more responses are needed (get the
 *                    queries with ares_dnssec_ctx_next_query()), ARES_TRUE
 *                    when validation is complete
 *  \return ARES_SUCCESS, or an error like ARES_ENOMEM when validation cannot
 *          go on
 */
ares_status_t ares_dnssec_req_run(ares_dnssec_req_t *req, ares_bool_t *done);

/*! The result of a completed request.
 *
 *  \param[in] req  Request
 *  \return The status, ARES_DNSSEC_INDETERMINATE when not completed
 */
ares_dnssec_status_t ares_dnssec_req_status(const ares_dnssec_req_t *req);

/*! Why a completed request did not end as ARES_DNSSEC_SECURE.
 *
 *  \param[in] req  Request
 *  \return A human readable explanation, or NULL
 */
const char *ares_dnssec_req_reason(const ares_dnssec_req_t *req);

/*! The DNS response code for the final name of a completed request.  When
 *  the zone uses compact denial of existence (RFC 9824), an authenticated
 *  NXNAME signal also results in NXDOMAIN.
 *
 *  \param[in] req  Request
 *  \return 0 (NOERROR) or 3 (NXDOMAIN)
 */
int ares_dnssec_req_rcode(const ares_dnssec_req_t *req);

/*! The TTL the validated answer can be cached for: the minimum of the
 *  record TTLs, their signatures' original TTLs and the time left until the
 *  signatures expire.
 *
 *  \param[in] req  Request
 *  \return TTL in seconds
 */
unsigned int ares_dnssec_req_ttl(const ares_dnssec_req_t *req);

/*! The number of records of the requested type in the validated answer.
 *
 *  \param[in] req  Request
 *  \return Number of records
 */
size_t ares_dnssec_req_count(const ares_dnssec_req_t *req);

/*! Get the RDATA of an answer record in canonical form (RFC 4034 section
 *  6.2): domain names in it are not compressed, and in lowercase for the
 *  record types listed there.
 *
 *  \param[in]  req     Request
 *  \param[in]  idx     Index of the record, less than ares_dnssec_req_count()
 *  \param[out] prdata  The RDATA, valid until the request is destroyed
 *  \param[out] prdlen  Length of the RDATA
 *  \return ARES_TRUE, or ARES_FALSE for a bad index
 */
ares_bool_t ares_dnssec_req_rdata(const ares_dnssec_req_t *req, size_t idx,
                                  const unsigned char **prdata, size_t *prdlen);

/*! Write the result of a completed request as a DNS response message: the
 *  question, and when the result is ARES_DNSSEC_SECURE or
 *  ARES_DNSSEC_INSECURE the CNAME and DNAME links followed (as CNAME
 *  records) and the validated answer records, with the AD flag set when
 *  secure.  Otherwise the response code is SERVFAIL and an OPT record has
 *  an Extended DNS Error (RFC 8914) with the reason.
 *
 *  \param[in] req  Request
 *  \param[in] buf  Buffer to append the message to
 *  \return ARES_SUCCESS, ARES_EFORMERR when the request is not complete, or
 *          ARES_ENOMEM
 */
ares_status_t ares_dnssec_req_response(const ares_dnssec_req_t *req,
                                       ares_buf_t              *buf);

/*! A text description of a status.
 *
 *  \param[in] status  Status
 *  \return The description, like "secure"
 */
const char *ares_dnssec_status_str(ares_dnssec_status_t status);

/*! For the test suite: make ares_query_dnssec() on a channel use other
 *  trust anchors, time and flags.
 *
 *  \param[in] channel  Channel
 *  \param[in] anchors  Trust anchors, one per line in the format of
 *                      ares_dnssec_ctx_add_anchor(), or NULL for the root
 *                      zone ones
 *  \param[in] now      Time to validate signatures against, or 0 for the
 *                      current time
 *  \param[in] flags    ARES_DNSSEC_* flags
 *  \return ARES_SUCCESS, ARES_EFORMERR or ARES_ENOMEM
 */
ares_status_t ares_dnssec_set_test_params(ares_channel_t *channel,
                                          const char *anchors, time_t now,
                                          unsigned int flags);

#endif /* ARES_DNSSEC_H */
