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

/* ares_query_dnssec(): runs the DNSSEC validator in dnssec/ on a channel.
 *
 * The validator does no I/O, it asks for the responses it needs.  This sends
 * those queries (with the DO and CD bits set) on the channel, hands the
 * responses to the validator and runs it again, until the validation is
 * complete.  The result is given to the caller as a DNS record built by the
 * validator from the validated data. */

#include "ares_private.h"
#include "dnssec/ares_dnssec.h"

/* The EDNS0 UDP payload size to announce, as recommended by DNS flag day
 * 2020.  Larger responses come over TCP. */
#define ARES_DNSSEC_EDNS_SIZE 1232
/* The DO bit in the EDNS0 flags, RFC 3225 */
#define ARES_DNSSEC_EDNS_DO 0x8000

typedef struct {
  ares_channel_t      *channel;
  ares_callback_dnsrec callback;
  void                *arg;
  ares_dnssec_ctx_t   *ctx;
  ares_dnssec_req_t   *req;
  /* queries sent whose callback has not been called yet */
  size_t               inflight;
  size_t               timeouts;
  /* ARES_ECANCELLED or ARES_EDESTRUCTION when a query ended with it: the
   * lookup is stopped and reports that status */
  ares_status_t        stopped;
  /* the caller's callback has been called */
  ares_bool_t          finished;
  /* ares_dnssec_progress() is running, and has to run again */
  ares_bool_t          running;
  ares_bool_t          again;
} ares_dnssec_lookup_t;

/* One query sent for a lookup */
typedef struct {
  ares_dnssec_lookup_t *lookup;
  unsigned short        qtype;
  char                  name[ARES_DNSSEC_NAME_STRLEN];
} ares_dnssec_query_t;

static void ares_dnssec_progress(ares_dnssec_lookup_t *lookup);

static void ares_dnssec_lookup_free(ares_dnssec_lookup_t *lookup)
{
  ares_dnssec_req_destroy(lookup->req);
  ares_dnssec_ctx_destroy(lookup->ctx);
  ares_free(lookup);
}

/* Call the caller's callback with the result */
static void ares_dnssec_finish(ares_dnssec_lookup_t *lookup,
                               ares_status_t         status)
{
  ares_dns_record_t *dnsrec = NULL;
  ares_buf_t        *buf    = NULL;
  unsigned char     *msg    = NULL;
  size_t             len    = 0;

  lookup->finished = ARES_TRUE;
  if (status != ARES_SUCCESS) {
    goto done;
  }

  buf = ares_buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }
  status = ares_dnssec_req_response(lookup->req, buf);
  if (status != ARES_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  msg = ares_buf_finish_bin(buf, &len);
  buf = NULL;
  if (msg == NULL) {
    status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }
  status = ares_dns_parse(msg, len, 0, &dnsrec);
  if (status != ARES_SUCCESS) {
    goto done;
  }
  status = ares_dns_query_reply_tostatus(
    ares_dns_record_get_rcode(dnsrec),
    ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));

done:
  lookup->callback(lookup->arg, status, lookup->timeouts, dnsrec);
  ares_dns_record_destroy(dnsrec);
  ares_buf_destroy(buf);
  ares_free(msg);
}

static void ares_dnssec_query_cb(void *arg, ares_status_t status,
                                 size_t                   timeouts,
                                 const ares_dns_record_t *dnsrec)
{
  ares_dnssec_query_t  *q      = arg;
  ares_dnssec_lookup_t *lookup = q->lookup;

  lookup->inflight--;
  lookup->timeouts += timeouts;
  if (status == ARES_ECANCELLED || status == ARES_EDESTRUCTION) {
    if (lookup->stopped == ARES_SUCCESS) {
      lookup->stopped = status;
    }
  }

  if (!lookup->finished) {
    unsigned char *msg = NULL;
    size_t         len = 0;
    ares_status_t  rv  = ARES_EFORMERR;

    /* The validator works on messages in wire format.  Records are written
     * back as they were parsed. */
    if (status == ARES_SUCCESS && dnsrec != NULL &&
        ares_dns_write(dnsrec, &msg, &len) == ARES_SUCCESS) {
      rv =
        ares_dnssec_ctx_add_response(lookup->ctx, q->name, q->qtype, msg, len);
      ares_free(msg);
    }
    if (rv != ARES_SUCCESS) {
      ares_dnssec_ctx_add_failure(lookup->ctx, q->name, q->qtype);
    }
  }

  ares_free(q);
  ares_dnssec_progress(lookup);
}

static ares_status_t ares_dnssec_send(ares_dnssec_lookup_t *lookup,
                                      const char *name, unsigned short qtype)
{
  ares_dns_record_t   *dnsrec = NULL;
  ares_dns_rr_t       *opt    = NULL;
  ares_dnssec_query_t *q;
  ares_status_t        status;

  q = ares_malloc_zero(sizeof(*q));
  if (q == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  q->lookup = lookup;
  q->qtype  = qtype;
  ares_strcpy(q->name, name, sizeof(q->name));

  /* RD and CD set (RFC 6840 section 5.9), DO set in EDNS0 (RFC 3225) */
  status = ares_dns_record_create(&dnsrec, 0,
                                  (unsigned short)(ARES_FLAG_RD | ARES_FLAG_CD),
                                  ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
  if (status == ARES_SUCCESS) {
    status = ares_dns_record_query_add(dnsrec, name, (ares_dns_rec_type_t)qtype,
                                       ARES_CLASS_IN);
  }
  if (status == ARES_SUCCESS) {
    status = ares_dns_record_rr_add(&opt, dnsrec, ARES_SECTION_ADDITIONAL, "",
                                    ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0);
  }
  if (status == ARES_SUCCESS) {
    status =
      ares_dns_rr_set_u16(opt, ARES_RR_OPT_UDP_SIZE, ARES_DNSSEC_EDNS_SIZE);
  }
  if (status == ARES_SUCCESS) {
    status = ares_dns_rr_set_u8(opt, ARES_RR_OPT_VERSION, 0);
  }
  if (status == ARES_SUCCESS) {
    status = ares_dns_rr_set_u16(opt, ARES_RR_OPT_FLAGS, ARES_DNSSEC_EDNS_DO);
  }
  if (status != ARES_SUCCESS) {
    ares_dns_record_destroy(dnsrec);
    ares_free(q);
    return status;
  }

  /* On failure the callback is called right away, and it frees 'q' */
  lookup->inflight++;
  status = ares_send_nolock(lookup->channel, NULL, 0, dnsrec,
                            ares_dnssec_query_cb, q, NULL);
  ares_dns_record_destroy(dnsrec);
  (void)status;
  return ARES_SUCCESS;
}

/* Run the validation as far as the responses allow and send the queries it
 * needs.  Frees the lookup when it is finished and no queries are left. */
static void ares_dnssec_progress(ares_dnssec_lookup_t *lookup)
{
  if (lookup->running) {
    /* called from a callback while sending, run again when done */
    lookup->again = ARES_TRUE;
    return;
  }
  lookup->running = ARES_TRUE;
  do {
    char           name[ARES_DNSSEC_NAME_STRLEN];
    unsigned short qtype;

    lookup->again = ARES_FALSE;
    if (lookup->finished) {
      break;
    }
    if (lookup->stopped != ARES_SUCCESS) {
      ares_dnssec_finish(lookup, lookup->stopped);
      break;
    } else {
      ares_bool_t   done   = ARES_FALSE;
      ares_status_t status = ares_dnssec_req_run(lookup->req, &done);
      if (status != ARES_SUCCESS || done) {
        ares_dnssec_finish(lookup, status);
        break;
      }
    }
    while (
      ares_dnssec_ctx_next_query(lookup->ctx, name, sizeof(name), &qtype)) {
      if (ares_dnssec_send(lookup, name, qtype) != ARES_SUCCESS) {
        ares_dnssec_ctx_add_failure(lookup->ctx, name, qtype);
        lookup->again = ARES_TRUE;
      }
    }
  } while (lookup->again);
  lookup->running = ARES_FALSE;

  if (lookup->finished && lookup->inflight == 0) {
    ares_dnssec_lookup_free(lookup);
  }
}

/* Set up the trust anchors and time the test suite asked for */
static ares_status_t ares_dnssec_test_params(const ares_channel_t *channel,
                                             ares_dnssec_ctx_t    *ctx)
{
  ares_buf_t   *buf;
  char        **anchors  = NULL;
  size_t        nanchors = 0;
  size_t        i;
  ares_status_t status;

  if (channel->dnssec_now != 0) {
    ares_dnssec_ctx_set_time(ctx, channel->dnssec_now);
  }
  ares_dnssec_ctx_set_flags(ctx, channel->dnssec_flags);
  if (channel->dnssec_anchors == NULL) {
    return ARES_SUCCESS;
  }

  buf = ares_buf_create_const((const unsigned char *)channel->dnssec_anchors,
                              ares_strlen(channel->dnssec_anchors));
  if (buf == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  status = ares_buf_split_str(buf, (const unsigned char *)"\n", 1,
                              ARES_BUF_SPLIT_TRIM, 0, &anchors, &nanchors);
  ares_buf_destroy(buf);
  if (status != ARES_SUCCESS) {
    return status;
  }
  ares_dnssec_ctx_clear_anchors(ctx);
  for (i = 0; i < nanchors && status == ARES_SUCCESS; i++) {
    status = ares_dnssec_ctx_add_anchor(ctx, anchors[i]);
  }
  ares_free_array(anchors, nanchors, ares_free);
  return status;
}

static ares_status_t ares_query_dnssec_nolock(ares_channel_t      *channel,
                                              const char          *name,
                                              ares_dns_rec_type_t  type,
                                              ares_callback_dnsrec callback,
                                              void                *arg)
{
  ares_dnssec_lookup_t *lookup;
  ares_dnssec_crypto_t  crypto;
  ares_status_t         status;

  if (name == NULL || (unsigned int)type > 0xffff) {
    status = ARES_EFORMERR;
    goto fail;
  }
  if (channel->dnssec_crypto_funcs.version == 0) {
    status = ARES_ENOTIMP;
    goto fail;
  }

  lookup = ares_malloc_zero(sizeof(*lookup));
  if (lookup == NULL) {
    status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto fail;            /* LCOV_EXCL_LINE: OutOfMemory */
  }
  lookup->channel  = channel;
  lookup->callback = callback;
  lookup->arg      = arg;

  crypto.alg_supported    = channel->dnssec_crypto_funcs.alg_supported;
  crypto.verify           = channel->dnssec_crypto_funcs.verify;
  crypto.digest_supported = channel->dnssec_crypto_funcs.digest_supported;
  crypto.digest           = channel->dnssec_crypto_funcs.digest;
  crypto.user_data        = channel->dnssec_crypto_data;
  status                  = ares_dnssec_ctx_create(&crypto, &lookup->ctx);
  if (status == ARES_SUCCESS) {
    status = ares_dnssec_test_params(channel, lookup->ctx);
  }
  if (status == ARES_SUCCESS) {
    status = ares_dnssec_req_create(lookup->ctx, name, (unsigned short)type,
                                    &lookup->req);
  }
  if (status != ARES_SUCCESS) {
    ares_dnssec_lookup_free(lookup);
    goto fail;
  }

  /* may call the callback before returning */
  ares_dnssec_progress(lookup);
  return ARES_SUCCESS;

fail:
  callback(arg, status, 0, NULL);
  return status;
}

ares_status_t ares_query_dnssec(ares_channel_t *channel, const char *name,
                                ares_dns_rec_type_t  type,
                                ares_callback_dnsrec callback, void *arg)
{
  ares_status_t status;

  if (channel == NULL || callback == NULL) {
    return ARES_EFORMERR;
  }

  ares_channel_lock(channel);
  status = ares_query_dnssec_nolock(channel, name, type, callback, arg);
  ares_channel_unlock(channel);
  return status;
}

ares_status_t ares_dnssec_set_test_params(ares_channel_t *channel,
                                          const char *anchors, time_t now,
                                          unsigned int flags)
{
  char *copy = NULL;

  if (channel == NULL) {
    return ARES_EFORMERR;
  }
  if (anchors != NULL) {
    copy = ares_strdup(anchors);
    if (copy == NULL) {
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  ares_channel_lock(channel);
  ares_free(channel->dnssec_anchors);
  channel->dnssec_anchors = copy;
  channel->dnssec_now     = now;
  channel->dnssec_flags   = flags;
  ares_channel_unlock(channel);
  return ARES_SUCCESS;
}

ares_status_t ares_set_dnssec_crypto_functions(
  ares_channel_t *channel, const struct ares_dnssec_crypto_functions *funcs,
  void *user_data)
{
  struct ares_dnssec_crypto_functions copy;

  if (channel == NULL) {
    return ARES_EFORMERR;
  }

  memset(&copy, 0, sizeof(copy));
  if (funcs != NULL) {
    if (funcs->version != 1) {
      return ARES_EFORMERR;
    }
    /* Copy individually for ABI compliance.  memcpy() with a sizeof would do
     * invalid reads */
    copy.version          = funcs->version;
    copy.alg_supported    = funcs->alg_supported;
    copy.verify           = funcs->verify;
    copy.digest_supported = funcs->digest_supported;
    copy.digest           = funcs->digest;
    if (copy.alg_supported == NULL || copy.verify == NULL ||
        copy.digest_supported == NULL || copy.digest == NULL) {
      return ARES_EFORMERR;
    }
    /* RFC 8624 section 3.1 and 3.3: every validator must support RSASHA256,
     * ECDSAP256SHA256, SHA-1 and SHA-256.  Without them, all zones would
     * be insecure (RFC 4035 section 5.2). */
    if (!copy.alg_supported(8, user_data) ||
        !copy.alg_supported(13, user_data) ||
        !copy.digest_supported(1, user_data) ||
        !copy.digest_supported(2, user_data)) {
      return ARES_EFORMERR;
    }
  }

  ares_channel_lock(channel);
  channel->dnssec_crypto_funcs = copy;
  channel->dnssec_crypto_data  = (funcs != NULL) ? user_data : NULL;
  ares_channel_unlock(channel);
  return ARES_SUCCESS;
}
