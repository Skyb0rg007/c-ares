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

/*
 * The DNSSEC validator.
 *
 * Validation of an answer is a pure function of the responses collected in
 * the context. ares_dnssec_req_run() evaluates it from the start every
 * time it is called. When a response it needs is missing, it asks for the
 * query (see query_get()) and the evaluation ends as pending. Once all
 * the responses it asked for are there, the next run gets further. The
 * results of expensive steps (validated zone keys, validated RRsets) are
 * cached, so repeating the evaluation is cheap.
 *
 * The chain of trust is built bottom-up from the signer names in RRSIG
 * records (RFC 4035 section 5): the keys of a signer zone are trusted if
 * the zone's DNSKEY RRset is signed by a key matching a trust anchor or a
 * validated DS RRset from the parent zone, whose keys are in turn trusted
 * the same way.
 *
 * Unsigned data is only accepted as insecure after a top-down walk from
 * the trust anchor has proven, with validated DS denials, that it is
 * below a delegation to an unsigned zone (see walk_down()). Anything else
 * is bogus.
 */

/* Upper limits, to bound the work an attacker can make us do */
#define DNSSEC_MAX_QUERIES   128 /* queries per context */
#define DNSSEC_MAX_VERIFY    128 /* signature verifications per context */
#define DNSSEC_MAX_KEY_TRIES 4   /* keys tried per RRSIG (same key tag) */
#define DNSSEC_MAX_SIGS      8   /* RRSIGs tried per RRset and signer */
#define DNSSEC_MAX_SIGNERS   3   /* signer zones tried per RRset */
#define DNSSEC_MAX_RRSET     256 /* records in an RRset */
#define DNSSEC_MAX_DENIAL    16  /* NSEC/NSEC3 records used in a proof */
#define DNSSEC_MAX_DS        16  /* DS records looked at */
#define DNSSEC_MAX_ZONEKEYS  32  /* DNSKEY records looked at */
#define DNSSEC_MAX_CHAIN     ARES_DNSSEC_MAX_CHAIN
#define DNSSEC_MAX_DEPTH     48  /* recursion depth */
#define DNSSEC_MAX_ZONES     24  /* nested zones in a chain of trust */
/* SHA-1 calculations for NSEC3 hashes per context */
#define DNSSEC_MAX_NSEC3_WORK 100000
#define DNSSEC_MAX_BYTES      (4 * 1024 * 1024) /* response data kept */
/* NSEC3 records with more iterations are bogus (RFC 9276 section 3.2). No
   answers are insecure because of iterations: that would let anyone forge
   denials in such zones (RFC 9276 section 4). Unbound uses the same limit. */
#define DNSSEC_NSEC3_MAX_ITER 150

#define DNSSEC_NONE ((size_t)-1)

/* evaluation status */
typedef enum {
  VS_PENDING = 0, /* waiting for responses */
  VS_SECURE,
  VS_INSECURE,
  VS_BOGUS,
  VS_INDETERMINATE
} vstat;

/* query states */
#define Q_WANTED 0
#define Q_SENT   1
#define Q_DONE   2

struct dnssec_query {
  struct dnssec_query *next;
  struct dnssec_msg   *msg; /* response, NULL if the query failed */
  unsigned char        name[DNSSEC_NAME_MAX]; /* in lowercase */
  unsigned short       qtype;
  unsigned char        state;
  /* for a DS query: the proof walk_down() got from it */
  unsigned char        wstat;
  unsigned char        wfact;
  unsigned char        wparent; /* labels in the zone above, plus one */
};

struct dnssec_anchor {
  struct dnssec_anchor *next;
  unsigned char         name[DNSSEC_NAME_MAX];
  unsigned char        *rdata;
  unsigned short        rdlen;
  unsigned short        type; /* DS or DNSKEY */
};

/* the validated keys of a zone, or why there are none */
struct dnssec_zone {
  struct dnssec_zone *next;
  unsigned char       name[DNSSEC_NAME_MAX];
  struct dnssec_msg  *msg; /* message with the DNSKEY RRset */
  size_t              keys[DNSSEC_MAX_ZONEKEYS];
  size_t              nkeys;
  char                reason[160];
  vstat               status;
};

struct ares_dnssec_ctx {
  ares_dnssec_crypto_t  crypto;
  struct dnssec_anchor *anchors;
  struct dnssec_query  *queries;
  struct dnssec_zone   *zones;
  time_t                fixed_now;
  unsigned int          flags;
  unsigned int          nqueries;
  unsigned int          nverify;
  unsigned long         nhash; /* SHA-1 calculations for NSEC3 */
  size_t                nbytes;
};

struct ares_dnssec_req {
  ares_dnssec_ctx_t   *ctx;
  struct dnssec_msg   *amsg;   /* message with the answer RRset */
  size_t               afirst; /* the first answer record in 'amsg' */
  size_t               acount;
  ares_buf_t          *rdata;  /* the answer RDATA, in canonical form */
  size_t              *rdoffs; /* where each one starts, acount + 1 */
  unsigned int         ttl;
  int                  rcode;
  ares_dnssec_status_t status;
  unsigned short       qtype;
  unsigned char        qname[DNSSEC_NAME_MAX];
  /* the CNAME and DNAME targets followed, in wire format */
  unsigned char        chain[ARES_DNSSEC_MAX_CHAIN][DNSSEC_NAME_MAX];
  size_t               nchain;
  char                 reason[256];
  ares_bool_t          done;
};

/* state of one evaluation run */
struct vctx {
  ares_dnssec_ctx_t   *ctx;
  ares_dnssec_req_t   *req;
  ares_status_t        error; /* fatal error, like out of memory */
  unsigned int         now;
  unsigned int         depth;
  unsigned int         nactive;
  const unsigned char *active[DNSSEC_MAX_ZONES]; /* zone_keys() in progress */
  char                 reason[256]; /* the latest reason for a failure */
  /* for names in reasons, here to keep them off the recursive frames */
  char                 nb[3][ARES_DNSSEC_NAME_STRLEN];
};

/* validated NSEC or NSEC3 records from one zone in one response */
struct nsecs {
  struct dnssec_msg   *m;
  size_t               rr[DNSSEC_MAX_DENIAL];
  size_t               n;
  unsigned char        zone[DNSSEC_NAME_MAX];
  unsigned int         ttl;
  ares_bool_t          nsec3;
  /* NSEC3 parameters, the same for all records used */
  const unsigned char *salt;
  unsigned char        saltlen;
  unsigned short       iterations;
};

/* A parsed RRSIG */
struct dnssec_sig {
  const unsigned char *rdata;
  const unsigned char *sig;
  size_t               siglen;
  unsigned int         ttl;
  unsigned int         origttl;
  unsigned int         expire;
  unsigned int         incept;
  unsigned short       covered;
  unsigned short       keytag;
  unsigned char        alg;
  unsigned char        labels;
  unsigned char        signer[DNSSEC_NAME_MAX];
};

/* facts a DS denial proves */
typedef enum {
  DS_UNSIGNED_CUT, /* a delegation without DS records */
  DS_OPTOUT,       /* in an NSEC3 opt-out span, maybe a delegation */
  DS_NOT_CUT,      /* the name exists, but is no delegation */
  DS_NO_NAME       /* the name does not exist */
} dsfact;

static vstat zone_keys(struct vctx *v, const unsigned char *zone,
                       struct dnssec_zone **pz);
static vstat walk_down(struct vctx *v, const unsigned char *name,
                       unsigned char *zone);
static vstat answer_rrset(struct vctx *v, struct dnssec_msg *m, size_t first,
                          const unsigned char *known, unsigned int *pttl);

static unsigned short rd16(const unsigned char *p)
{
  return (unsigned short)((p[0] << 8) | p[1]);
}

static unsigned int rd32(const unsigned char *p)
{
  return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
         ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

/* Write the decimal 'num' to 'out' (at least 11 bytes), return its length */
static size_t fmt_uint(char *out, unsigned int num)
{
  char   tmp[10];
  size_t n = 0;
  size_t i;
  do {
    tmp[n++]  = (char)('0' + (num % 10));
    num      /= 10;
  } while (num);
  for (i = 0; i < n; i++) {
    out[i] = tmp[n - 1 - i];
  }
  out[n] = 0;
  return n;
}

/* Set the reason for a failure. The format only knows %s and %u. */
static void why(struct vctx *v, const char *fmt, ...)
{
  char   *out  = v->reason;
  size_t  left = sizeof(v->reason) - 1;
  va_list ap;

  va_start(ap, fmt);
  while (*fmt && left) {
    char        num[11];
    const char *add = num;
    size_t      len;
    if ((fmt[0] == '%') && (fmt[1] == 's')) {
      add  = va_arg(ap, const char *);
      len  = ares_strlen(add);
      fmt += 2;
    } else if ((fmt[0] == '%') && (fmt[1] == 'u')) {
      len  = fmt_uint(num, va_arg(ap, unsigned int));
      fmt += 2;
    } else {
      add = fmt++;
      len = 1;
    }
    if (len > left) {
      len = left;
    }
    memcpy(out, add, len);
    out  += len;
    left -= len;
  }
  va_end(ap);
  *out = 0;
}

/* presentation format of a name, for reason texts */
#define NAMESTR(n, buf) (ares_dnssec_name_str(n, buf, sizeof(buf)), buf)

static const char *typestr(unsigned short type, char *buf, size_t len)
{
  switch (type) {
    case DNSSEC_TYPE_A:
      return "A";
    case DNSSEC_TYPE_NS:
      return "NS";
    case DNSSEC_TYPE_CNAME:
      return "CNAME";
    case DNSSEC_TYPE_SOA:
      return "SOA";
    case DNSSEC_TYPE_AAAA:
      return "AAAA";
    case DNSSEC_TYPE_DNAME:
      return "DNAME";
    case DNSSEC_TYPE_DS:
      return "DS";
    case DNSSEC_TYPE_NSEC:
      return "NSEC";
    case DNSSEC_TYPE_DNSKEY:
      return "DNSKEY";
    case DNSSEC_TYPE_NSEC3:
      return "NSEC3";
    case DNSSEC_TYPE_TLSA:
      return "TLSA";
    case DNSSEC_TYPE_HTTPS:
      return "HTTPS";
    default:
      if (len >= 15) {
        memcpy(buf, "TYPE", 4);
        fmt_uint(&buf[4], type);
      } else {
        buf[0] = 0;
      }
      return buf;
  }
}

static vstat vs_oom(struct vctx *v)
{
  v->error = ARES_ENOMEM;
  why(v, "out of memory");
  return VS_INDETERMINATE;
}

/* Is the signature algorithm acceptable? */
static ares_bool_t alg_ok(ares_dnssec_ctx_t *ctx, unsigned char alg)
{
  if (((alg == DNSSEC_ALG_RSASHA1) || (alg == DNSSEC_ALG_RSASHA1_NSEC3)) &&
      !(ctx->flags & ARES_DNSSEC_ALLOW_SHA1)) {
    return ARES_FALSE;
  }
  return ares_dnssec_alg_supported(&ctx->crypto, alg);
}

/*
 * Queries
 */

static struct dnssec_query *query_find(ares_dnssec_ctx_t   *ctx,
                                       const unsigned char *name,
                                       unsigned short       qtype)
{
  struct dnssec_query *q;
  for (q = ctx->queries; q; q = q->next) {
    if ((q->qtype == qtype) && ares_dnssec_name_eq(q->name, name)) {
      return q;
    }
  }
  return NULL;
}

/* Get the response for a query. Returns VS_SECURE (meaning "here it is")
   with *pmsg set, VS_PENDING when the query is not answered yet (and asks
   for it if it was not asked for before) or VS_INDETERMINATE when the
   query failed. */
static vstat query_get(struct vctx *v, const unsigned char *name,
                       unsigned short qtype, struct dnssec_msg **pmsg)
{
  ares_dnssec_ctx_t   *ctx = v->ctx;
  struct dnssec_query *q   = query_find(ctx, name, qtype);
  char                 tbuf[16];

  *pmsg = NULL;
  if (!q) {
    if (ctx->nqueries >= DNSSEC_MAX_QUERIES) {
      why(v, "too many queries");
      return VS_INDETERMINATE;
    }
    q = ares_malloc_zero(sizeof(*q));
    if (!q) {
      return vs_oom(v);
    }
    ares_dnssec_name_lower(q->name, name);
    q->qtype     = qtype;
    q->state     = Q_WANTED;
    q->next      = ctx->queries;
    ctx->queries = q;
    ctx->nqueries++;
    return VS_PENDING;
  }
  if (q->state != Q_DONE) {
    return VS_PENDING;
  }
  if (!q->msg) {
    why(v, "lookup of %s %s failed", NAMESTR(name, v->nb[0]),
        typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_INDETERMINATE;
  }
  if ((q->msg->rcode != DNSSEC_RCODE_NOERROR) &&
      (q->msg->rcode != DNSSEC_RCODE_NXDOMAIN)) {
    why(v, "lookup of %s %s: response code %u", NAMESTR(name, v->nb[0]),
        typestr(qtype, tbuf, sizeof(tbuf)), q->msg->rcode);
    return VS_INDETERMINATE;
  }
  *pmsg = q->msg;
  return VS_SECURE;
}

/*
 * RRsets
 */

static ares_bool_t rr_same_set(const struct dnssec_msg *m,
                               const struct dnssec_rr  *a,
                               const struct dnssec_rr  *b)
{
  return (a->section == b->section) && (a->type == b->type) &&
         (a->rclass == b->rclass) &&
         ares_dnssec_name_eq(DNSSEC_RR_OWNER(m, a), DNSSEC_RR_OWNER(m, b));
}

/* Find the first record of the RRset 'name'/'type' in 'section' */
static size_t rrset_find(const struct dnssec_msg *m, unsigned char section,
                         const unsigned char *name, unsigned short type)
{
  size_t i;
  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    if ((rr->section == section) && (rr->type == type) &&
        (rr->rclass == DNSSEC_CLASS_IN) &&
        ares_dnssec_name_eq(DNSSEC_RR_OWNER(m, rr), name)) {
      return i;
    }
  }
  return DNSSEC_NONE;
}

/* Is 'i' the first record of its RRset? */
static ares_bool_t rrset_first(const struct dnssec_msg *m, size_t i)
{
  size_t j;
  for (j = 0; j < i; j++) {
    if (rr_same_set(m, &m->rrs[j], &m->rrs[i])) {
      return ARES_FALSE;
    }
  }
  return ARES_TRUE;
}

/* Does RRSIG 'rr' cover the RRset starting at 'set'? */
static ares_bool_t rrsig_covers(const struct dnssec_msg *m,
                                const struct dnssec_rr  *rr,
                                const struct dnssec_rr  *set)
{
  return (rr->type == DNSSEC_TYPE_RRSIG) && (rr->section == set->section) &&
         (rr->rclass == set->rclass) && (rr->rdlen >= 18) &&
         (rd16(DNSSEC_RR_RDATA(m, rr)) == set->type) &&
         ares_dnssec_name_eq(DNSSEC_RR_OWNER(m, rr), DNSSEC_RR_OWNER(m, set));
}

static ares_bool_t sig_parse(const struct dnssec_msg *m,
                             const struct dnssec_rr *rr, struct dnssec_sig *s)
{
  const unsigned char *d   = DNSSEC_RR_RDATA(m, rr);
  size_t               off = 18;
  if (rr->rdlen < 18) {
    return ARES_FALSE;
  }
  /* the signer name is never compressed, RFC 4034 section 3.1.7 */
  if (ares_dnssec_read_name(d, rr->rdlen, &off, ARES_FALSE, s->signer) ||
      (off >= rr->rdlen)) {
    return ARES_FALSE;
  }
  ares_dnssec_name_lower(s->signer, s->signer);
  s->rdata   = d;
  s->covered = rd16(d);
  s->alg     = d[2];
  s->labels  = d[3];
  s->origttl = rd32(&d[4]);
  s->expire  = rd32(&d[8]);
  s->incept  = rd32(&d[12]);
  s->keytag  = rd16(&d[16]);
  s->sig     = &d[off];
  s->siglen  = rr->rdlen - off;
  s->ttl     = rr->ttl;
  return ARES_TRUE;
}

/* a <= b in serial number arithmetic, RFC 1982 */
static ares_bool_t serial_le(unsigned int a, unsigned int b)
{
  return (int32_t)(b - a) >= 0;
}

struct canon_rdata {
  const unsigned char *p;
  size_t               len;
};

static int canon_rdata_cmp(const void *a, const void *b)
{
  const struct canon_rdata *x   = a;
  const struct canon_rdata *y   = b;
  size_t                    len = (x->len < y->len) ? x->len : y->len;
  int                       rc  = len ? memcmp(x->p, y->p, len) : 0;
  if (rc) {
    return rc;
  }
  return (x->len < y->len) ? -1 : ((x->len > y->len) ? 1 : 0);
}

/* Build the data an RRSIG signs, RFC 4034 section 3.1.8.1 and RFC 4035
   section 5.3.2 */
static ares_status_t sig_data(const struct dnssec_msg *m, size_t first,
                              const struct dnssec_sig *s, ares_buf_t *out)
{
  const struct dnssec_rr *set   = &m->rrs[first];
  const unsigned char    *owner = DNSSEC_RR_OWNER(m, set);
  unsigned char           name[DNSSEC_NAME_MAX];
  size_t                  namelen;
  ares_buf_t             *rd = NULL;
  const unsigned char    *rdp;
  size_t                  rdlen;
  struct canon_rdata     *list = NULL;
  size_t                 *offs = NULL;
  size_t                  n    = 0;
  size_t                  i;
  unsigned char           hdr[10];
  ares_status_t           result = ARES_SUCCESS;

  /* the owner name, with the wildcard restored */
  if (s->labels < ares_dnssec_name_sig_labels(owner)) {
    const unsigned char *suffix = ares_dnssec_name_suffix(owner, s->labels);
    name[0]                     = 1;
    name[1]                     = '*';
    memcpy(&name[2], suffix, ares_dnssec_name_len(suffix));
  } else {
    memcpy(name, owner, ares_dnssec_name_len(owner));
  }
  ares_dnssec_name_lower(name, name);
  namelen = ares_dnssec_name_len(name);

  /* RRSIG RDATA without the signature, with the signer in canonical form */
  if (ares_buf_append(out, s->rdata, 18) ||
      ares_buf_append(out, s->signer, ares_dnssec_name_len(s->signer))) {
    return ARES_ENOMEM;
  }

  rd   = ares_buf_create();
  offs = ares_malloc_zero_array(DNSSEC_MAX_RRSET + 1, sizeof(size_t));
  list = ares_malloc_zero_array(DNSSEC_MAX_RRSET, sizeof(struct canon_rdata));
  if (!rd || !offs || !list) {
    result = ARES_ENOMEM;
    goto out;
  }
  for (i = first; i < m->nrrs; i++) {
    if (!rr_same_set(m, &m->rrs[i], set)) {
      continue;
    }
    if (n >= DNSSEC_MAX_RRSET) {
      result = ARES_EBADRESP;
      goto out;
    }
    offs[n++] = ares_buf_len(rd);
    result    = ares_dnssec_rdata_canonical(m, &m->rrs[i], rd);
    if (result) {
      goto out;
    }
  }
  offs[n] = ares_buf_len(rd);
  rdp     = ares_buf_peek(rd, &rdlen);
  for (i = 0; i < n; i++) {
    list[i].p   = rdp ? rdp + offs[i] : NULL;
    list[i].len = offs[i + 1] - offs[i];
    if (list[i].len > 0xffff) {
      result = ARES_EBADRESP;
      goto out;
    }
  }
  qsort(list, n, sizeof(struct canon_rdata), canon_rdata_cmp);

  hdr[0] = (unsigned char)(set->type >> 8);
  hdr[1] = (unsigned char)set->type;
  hdr[2] = (unsigned char)(set->rclass >> 8);
  hdr[3] = (unsigned char)set->rclass;
  memcpy(&hdr[4], &s->rdata[4], 4); /* original TTL */
  for (i = 0; i < n; i++) {
    /* RFC 4034 section 6.3: duplicates are only included once */
    if (i && !canon_rdata_cmp(&list[i - 1], &list[i])) {
      continue;
    }
    hdr[8] = (unsigned char)(list[i].len >> 8);
    hdr[9] = (unsigned char)list[i].len;
    if (ares_buf_append(out, name, namelen) ||
        ares_buf_append(out, hdr, sizeof(hdr)) ||
        (list[i].len && ares_buf_append(out, list[i].p, list[i].len))) {
      result = ARES_ENOMEM;
      goto out;
    }
  }

out:
  ares_free(offs);
  ares_free(list);
  ares_buf_destroy(rd);
  return result;
}

/* Verify the RRset starting at 'first' in 'm' with an RRSIG made by
   'signer' and one of the DNSKEY records 'keys' (indexes into 'km').
   RFC 4035 section 5.3. On success, sets the TTL the RRset may be used
   for and the RRSIG Labels value of the signature. */
static vstat rrset_verify(struct vctx *v, const struct dnssec_msg *m,
                          size_t first, const unsigned char *signer,
                          const struct dnssec_msg *km, const size_t *keys,
                          size_t nkeys, unsigned int *pttl,
                          unsigned int *plabels)
{
  const struct dnssec_rr *set     = &m->rrs[first];
  const unsigned char    *owner   = DNSSEC_RR_OWNER(m, set);
  unsigned int            olabels = ares_dnssec_name_sig_labels(owner);
  unsigned int            tries   = 0;
  char                    tbuf[16];
  ares_buf_t             *data = NULL;
  const unsigned char    *dp;
  size_t                  dlen;
  size_t                  i;
  vstat                   result = VS_BOGUS;

  why(v, "no valid signature for %s %s", NAMESTR(owner, v->nb[0]),
      typestr(set->type, tbuf, sizeof(tbuf)));

  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    struct dnssec_sig       s;
    unsigned int            ktries = 0;
    size_t                  k;

    if (!rrsig_covers(m, rr, set) || !sig_parse(m, rr, &s) ||
        !ares_dnssec_name_eq(s.signer, signer)) {
      continue;
    }
    /* RFC 4035 section 5.3.1 */
    if (s.labels > olabels) {
      why(v, "RRSIG for %s %s has a bad label count", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    if (!alg_ok(v->ctx, s.alg)) {
      why(v, "RRSIG for %s %s uses unsupported algorithm %u",
          NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)),
          s.alg);
      continue;
    }
    if (!serial_le(s.incept, s.expire) || !serial_le(v->now, s.expire)) {
      why(v, "RRSIG for %s %s has expired", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    if (!serial_le(s.incept, v->now)) {
      why(v, "RRSIG for %s %s is not valid yet", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    /* only signatures that can be valid count, junk ones must not hide
       them (RFC 6840 5.4) */
    for (k = 0; k < nkeys; k++) {
      const struct dnssec_rr *key = &km->rrs[keys[k]];
      const unsigned char    *kd  = DNSSEC_RR_RDATA(km, key);
      if ((kd[3] == s.alg) &&
          (ares_dnssec_keytag(kd, key->rdlen) == s.keytag)) {
        break;
      }
    }
    if (k == nkeys) {
      why(v, "RRSIG for %s %s by key %u of %s: no such key",
          NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)),
          s.keytag, NAMESTR(signer, v->nb[1]));
      continue;
    }
    if (++tries > DNSSEC_MAX_SIGS) {
      break;
    }
    ares_buf_destroy(data);
    data = ares_buf_create();
    if (!data) {
      result = vs_oom(v);
      goto out;
    }
    if (sig_data(m, first, &s, data)) {
      why(v, "cannot build signed data for %s %s", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }

    dp = ares_buf_peek(data, &dlen);
    for (k = 0; k < nkeys; k++) {
      const struct dnssec_rr *key = &km->rrs[keys[k]];
      const unsigned char    *kd  = DNSSEC_RR_RDATA(km, key);
      ares_status_t           rc;
      if ((kd[3] != s.alg) ||
          (ares_dnssec_keytag(kd, key->rdlen) != s.keytag)) {
        continue;
      }
      if (++ktries > DNSSEC_MAX_KEY_TRIES) {
        break;
      }
      if (v->ctx->nverify >= DNSSEC_MAX_VERIFY) {
        why(v, "too many signature verifications");
        result = VS_INDETERMINATE;
        goto out;
      }
      v->ctx->nverify++;
      rc = ares_dnssec_verify(&v->ctx->crypto, s.alg, kd + 4, key->rdlen - 4u,
                              dp, dlen, s.sig, s.siglen);
      if (!rc) {
        /* RFC 4035 section 5.3.3 */
        unsigned int ttl = s.ttl;
        size_t       j;
        if (s.origttl < ttl) {
          ttl = s.origttl;
        }
        if (s.expire - v->now < ttl) {
          ttl = s.expire - v->now;
        }
        for (j = first; j < m->nrrs; j++) {
          if (rr_same_set(m, &m->rrs[j], set) && (m->rrs[j].ttl < ttl)) {
            ttl = m->rrs[j].ttl;
          }
        }
        *pttl    = ttl;
        *plabels = s.labels;
        result   = VS_SECURE;
        goto out;
      }
      if (rc == ARES_ENOMEM) {
        result = vs_oom(v);
        goto out;
      }
      why(v, "RRSIG for %s %s by key %u does not verify",
          NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)),
          s.keytag);
    }
  }
out:
  ares_buf_destroy(data);
  return result;
}

static int rank(vstat r)
{
  /* the order of preference when there are several ways to validate */
  switch (r) {
    case VS_SECURE:
      return 4;
    case VS_INSECURE:
      return 3;
    case VS_INDETERMINATE:
      return 2;
    default:
      return 1;
  }
}

/* The closest trust anchor at or above 'name', or NULL */
static const unsigned char *deepest_anchor(ares_dnssec_ctx_t   *ctx,
                                           const unsigned char *name)
{
  struct dnssec_anchor *a;
  const unsigned char  *ta = NULL;
  for (a = ctx->anchors; a; a = a->next) {
    if (ares_dnssec_name_sub(name, a->name) &&
        (!ta ||
         (ares_dnssec_name_labels(a->name) > ares_dnssec_name_labels(ta)))) {
      ta = a->name;
    }
  }
  return ta;
}

/* The lowest TTL in the RRset starting at 'first', RFC 2181 5.2 */
static unsigned int rrset_ttl(const struct dnssec_msg *m, size_t first)
{
  unsigned int ttl = m->rrs[first].ttl;
  size_t       i;
  for (i = first + 1; i < m->nrrs; i++) {
    if (rr_same_set(m, &m->rrs[i], &m->rrs[first]) && (m->rrs[i].ttl < ttl)) {
      ttl = m->rrs[i].ttl;
    }
  }
  return ttl;
}

/* Is the record at 'first' the only one in its RRset? */
static ares_bool_t rrset_single(const struct dnssec_msg *m, size_t first)
{
  size_t i;
  for (i = first + 1; i < m->nrrs; i++) {
    if (rr_same_set(m, &m->rrs[i], &m->rrs[first])) {
      return ARES_FALSE;
    }
  }
  return ARES_TRUE;
}

/* Does the RRset starting at 'first' have an RRSIG made by 'signer'? */
static ares_bool_t rrset_signed_by(const struct dnssec_msg *m, size_t first,
                                   const unsigned char *signer)
{
  size_t i;
  for (i = 0; i < m->nrrs; i++) {
    struct dnssec_sig s;
    if (rrsig_covers(m, &m->rrs[i], &m->rrs[first]) &&
        sig_parse(m, &m->rrs[i], &s) && ares_dnssec_name_eq(s.signer, signer)) {
      return ARES_TRUE;
    }
  }
  return ARES_FALSE;
}

/* Validate the RRset starting at 'first', with the keys of the zones that
   signed it. An unsigned RRset is insecure when walk_down() proves it is
   in an unsigned zone, and bogus otherwise. On success, sets the TTL the
   RRset may be used for, the RRSIG Labels value of the signature and the
   signer (a pointer into the owner name). */
static vstat rrset_validate(struct vctx *v, struct dnssec_msg *m, size_t first,
                            unsigned int *pttl, unsigned int *plabels,
                            const unsigned char **psigner)
{
  struct dnssec_rr    *set   = &m->rrs[first];
  const unsigned char *owner = DNSSEC_RR_OWNER(m, set);
  /* DS records are in the parent zone, validated with the anchors above */
  const unsigned char *ta =
    (set->type != DNSSEC_TYPE_DS)
      ? deepest_anchor(v->ctx, owner)
      : (owner[0] ? deepest_anchor(v->ctx, owner + 1 + owner[0]) : NULL);
  unsigned int olabels = ares_dnssec_name_labels(owner);
  unsigned int tlabels = ta ? ares_dnssec_name_labels(ta) : 0;
  /* the signers seen, by their number of labels: they are all at or above
     the owner name */
  ares_bool_t  cand[DNSSEC_LABELS_MAX + 1];
  unsigned int ncand = 0;
  unsigned int tries = 0;
  unsigned int l;
  ares_bool_t  have_sig = ARES_FALSE;
  ares_bool_t  pending  = ARES_FALSE;
  vstat        best     = VS_BOGUS;
  char         tbuf[16];
  size_t       i;

  *pttl    = rrset_ttl(m, first);
  *plabels = ares_dnssec_name_sig_labels(owner);
  *psigner = NULL;
  if (set->vstat) {
    *pttl = set->vttl;
    if (set->vstat == VS_SECURE) {
      *plabels = set->vlabels;
      *psigner = ares_dnssec_name_suffix(owner, set->vsigner);
    }
    return (vstat)set->vstat;
  }

  memset(cand, 0, sizeof(cand));
  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    struct dnssec_sig       s;
    unsigned int            sl;
    ares_bool_t             ok;
    if (!rrsig_covers(m, rr, set)) {
      continue;
    }
    have_sig = ARES_TRUE;
    if (!sig_parse(m, rr, &s)) {
      continue;
    }
    /* RFC 4035 5.3.1: the signer is the zone that contains the RRset. The
       DNSKEY RRset is at the zone apex, the DS RRset is in the parent. */
    sl = ares_dnssec_name_labels(s.signer);
    if (set->type == DNSSEC_TYPE_DNSKEY) {
      ok = (sl == olabels);
    } else if (set->type == DNSSEC_TYPE_DS) {
      ok = (sl < olabels);
    } else {
      ok = ARES_TRUE;
    }
    /* Only zones at or below the closest trust anchor. Above it, an
       unsigned zone would make the data look insecure. */
    if (ok && ta && (sl >= tlabels) && ares_dnssec_name_sub(owner, s.signer) &&
        !cand[sl]) {
      cand[sl] = ARES_TRUE;
      ncand++;
    }
  }

  if (!have_sig) {
    vstat r = walk_down(v, owner, NULL);
    if (r == VS_SECURE) {
      why(v, "%s %s is not signed", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      r = VS_BOGUS;
    }
    if ((r != VS_PENDING) && !v->error) {
      set->vstat = (unsigned char)r;
      set->vttl  = *pttl;
    }
    return r;
  }
  if (!ta) {
    why(v, "no trust anchor for %s", NAMESTR(owner, v->nb[0]));
    return VS_INDETERMINATE;
  }
  if (!ncand) {
    why(v, "RRSIG for %s %s has a bad signer name", NAMESTR(owner, v->nb[0]),
        typestr(set->type, tbuf, sizeof(tbuf)));
    set->vstat = VS_BOGUS;
    set->vttl  = *pttl;
    return VS_BOGUS;
  }

  /* the closest zone first, it is the one that should have signed */
  for (l = olabels + 1; l-- > tlabels;) {
    const unsigned char *signer = ares_dnssec_name_suffix(owner, l);
    struct dnssec_zone  *z;
    vstat                r;
    if (!cand[l]) {
      continue;
    }
    if (++tries > DNSSEC_MAX_SIGNERS) {
      break;
    }
    r = zone_keys(v, signer, &z);
    if (r == VS_PENDING) {
      pending = ARES_TRUE;
      continue;
    }
    if (r == VS_SECURE) {
      r = rrset_verify(v, m, first, z->name, z->msg, z->keys, z->nkeys, pttl,
                       plabels);
      if (r == VS_SECURE) {
        set->vstat   = VS_SECURE;
        set->vttl    = *pttl;
        set->vlabels = (unsigned char)*plabels;
        set->vsigner = (unsigned char)l;
        *psigner     = signer;
        return VS_SECURE;
      }
    }
    if (rank(r) > rank(best)) {
      best = r;
    }
  }
  *pttl    = rrset_ttl(m, first);
  *plabels = ares_dnssec_name_sig_labels(owner);
  if (pending) {
    return VS_PENDING;
  }
  if (!v->error) {
    set->vstat = (unsigned char)best;
    set->vttl  = *pttl;
  }
  return best;
}

/*
 * Zone keys and the chain of trust
 */

static struct dnssec_zone *zone_find(ares_dnssec_ctx_t   *ctx,
                                     const unsigned char *name)
{
  struct dnssec_zone *z;
  for (z = ctx->zones; z; z = z->next) {
    if (ares_dnssec_name_eq(z->name, name)) {
      return z;
    }
  }
  return NULL;
}

static ares_bool_t anchored(ares_dnssec_ctx_t *ctx, const unsigned char *zone)
{
  struct dnssec_anchor *a;
  for (a = ctx->anchors; a; a = a->next) {
    if (ares_dnssec_name_eq(a->name, zone)) {
      return ARES_TRUE;
    }
  }
  return ARES_FALSE;
}

/* Is there a trust anchor at or above 'name'? */
static ares_bool_t covered(ares_dnssec_ctx_t *ctx, const unsigned char *name)
{
  struct dnssec_anchor *a;
  for (a = ctx->anchors; a; a = a->next) {
    if (ares_dnssec_name_sub(name, a->name)) {
      return ARES_TRUE;
    }
  }
  return ARES_FALSE;
}

struct dsref {
  const unsigned char *rdata;
  size_t               rdlen;
};

static void ds_add(ares_dnssec_ctx_t *ctx, struct dsref *ds, size_t *pnds,
                   const unsigned char *rdata, size_t rdlen)
{
  /* RFC 4035 5.2 and RFC 6840 5.2: DS records for unsupported algorithms
     and digest types are disregarded */
  if ((*pnds < DNSSEC_MAX_DS) && (rdlen > 4) && alg_ok(ctx, rdata[2]) &&
      ares_dnssec_digest_supported(&ctx->crypto, rdata[3])) {
    ds[*pnds].rdata = rdata;
    ds[*pnds].rdlen = rdlen;
    (*pnds)++;
  }
}

/* Validate the DNSKEY RRset of zone 'z' in 'km' with the trust anchors of
   the zone or the validated DS RRset starting at 'dfirst' in 'dm'. RFC
   4035 section 5.2. */
static vstat dnskey_validate(struct vctx *v, struct dnssec_zone *z,
                             struct dnssec_msg *km, const struct dnssec_msg *dm,
                             size_t dfirst, ares_bool_t by_anchor)
{
  ares_dnssec_ctx_t *ctx = v->ctx;
  struct dsref       ds[DNSSEC_MAX_DS];
  struct dsref       tk[DNSSEC_MAX_DS];
  size_t             sep[DNSSEC_MAX_ZONEKEYS];
  size_t             nds    = 0;
  size_t             ntk    = 0;
  size_t             nsep   = 0;
  size_t             looked = 0;
  ares_bool_t        sha2   = ARES_FALSE;
  size_t             kfirst;
  size_t             olen;
  size_t             i;
  unsigned int       ttl;
  unsigned int       labels;
  vstat              r;

  kfirst = rrset_find(km, DNSSEC_SECT_ANSWER, z->name, DNSSEC_TYPE_DNSKEY);
  if (kfirst == DNSSEC_NONE) {
    why(v, "no DNSKEY records for %s", NAMESTR(z->name, v->nb[0]));
    return VS_BOGUS;
  }

  if (by_anchor) {
    struct dnssec_anchor *a;
    for (a = ctx->anchors; a; a = a->next) {
      if (!ares_dnssec_name_eq(a->name, z->name)) {
        continue;
      }
      if (a->type == DNSSEC_TYPE_DS) {
        ds_add(ctx, ds, &nds, a->rdata, a->rdlen);
      } else if ((ntk < DNSSEC_MAX_DS) && alg_ok(ctx, a->rdata[3])) {
        tk[ntk].rdata = a->rdata;
        tk[ntk].rdlen = a->rdlen;
        ntk++;
      }
    }
  } else {
    for (i = dfirst; i < dm->nrrs; i++) {
      if (rr_same_set(dm, &dm->rrs[i], &dm->rrs[dfirst])) {
        ds_add(ctx, ds, &nds, DNSSEC_RR_RDATA(dm, &dm->rrs[i]),
               dm->rrs[i].rdlen);
      }
    }
  }
  if (!nds && !ntk) {
    why(v, "no supported algorithms in the DS records of %s",
        NAMESTR(z->name, v->nb[0]));
    return VS_INSECURE;
  }
  /* RFC 4509 section 3: ignore SHA-1 DS records when there are SHA-2
     ones */
  for (i = 0; i < nds; i++) {
    if (ds[i].rdata[3] != DNSSEC_DIGEST_SHA1) {
      sha2 = ARES_TRUE;
    }
  }

  /* find the keys the DS records or trust anchors point to */
  olen = ares_dnssec_name_len(z->name);
  for (i = kfirst; (i < km->nrrs) && (nsep < DNSSEC_MAX_ZONEKEYS); i++) {
    const struct dnssec_rr *rr = &km->rrs[i];
    const unsigned char    *kd = DNSSEC_RR_RDATA(km, rr);
    unsigned short          flags;
    unsigned short          tag;
    ares_bool_t             match = ARES_FALSE;
    size_t                  j;
    if (!rr_same_set(km, rr, &km->rrs[kfirst])) {
      continue;
    }
    if (++looked > DNSSEC_MAX_ZONEKEYS * 2) {
      break;
    }
    if (rr->rdlen < 5) {
      continue;
    }
    flags = rd16(kd);
    if ((kd[2] != 3) || !(flags & DNSSEC_DNSKEY_ZONE) ||
        (flags & DNSSEC_DNSKEY_REVOKE) || !alg_ok(ctx, kd[3])) {
      continue;
    }
    for (j = 0; (j < ntk) && !match; j++) {
      /* compare protocol, algorithm and key, not the flags */
      match = (tk[j].rdlen == rr->rdlen) &&
              !memcmp(tk[j].rdata + 2, kd + 2, rr->rdlen - 2u);
    }
    tag = ares_dnssec_keytag(kd, rr->rdlen);
    for (j = 0; (j < nds) && !match; j++) {
      const unsigned char *d = ds[j].rdata;
      unsigned char        digest[DNSSEC_DIGEST_MAX];
      size_t               dlen;
      if ((rd16(d) != tag) || (d[2] != kd[3]) ||
          (sha2 && (d[3] == DNSSEC_DIGEST_SHA1))) {
        continue;
      }
      /* digest = hash(owner name | DNSKEY RDATA), RFC 4034 section 5.1.4.
         z->name is in lowercase. */
      dlen  = ares_dnssec_digest(&v->ctx->crypto, d[3], z->name, olen, kd,
                                 rr->rdlen, digest);
      match = dlen && (dlen == ds[j].rdlen - 4) && !memcmp(digest, d + 4, dlen);
    }
    if (match) {
      sep[nsep++] = i;
    }
  }
  if (!nsep) {
    why(v, "no DNSKEY of %s matches its %s", NAMESTR(z->name, v->nb[0]),
        by_anchor ? "trust anchor" : "DS records");
    return VS_BOGUS;
  }

  r = rrset_verify(v, km, kfirst, z->name, km, sep, nsep, &ttl, &labels);
  if (r != VS_SECURE) {
    return r;
  }
  if (labels != ares_dnssec_name_sig_labels(z->name)) {
    why(v, "DNSKEY RRSIG for %s has a bad label count",
        NAMESTR(z->name, v->nb[0]));
    return VS_BOGUS;
  }
  km->rrs[kfirst].vstat   = VS_SECURE;
  km->rrs[kfirst].vttl    = ttl;
  km->rrs[kfirst].vlabels = (unsigned char)labels;
  km->rrs[kfirst].vsigner = (unsigned char)ares_dnssec_name_labels(z->name);

  /* Any key of the zone can sign data in it, RFC 6840 section 6.2 */
  z->msg   = km;
  z->nkeys = 0;
  for (i = kfirst; (i < km->nrrs) && (z->nkeys < DNSSEC_MAX_ZONEKEYS); i++) {
    const struct dnssec_rr *rr = &km->rrs[i];
    const unsigned char    *kd = DNSSEC_RR_RDATA(km, rr);
    if (!rr_same_set(km, rr, &km->rrs[kfirst]) || (rr->rdlen < 5)) {
      continue;
    }
    if ((kd[2] == 3) && (rd16(kd) & DNSSEC_DNSKEY_ZONE) &&
        !(rd16(kd) & DNSSEC_DNSKEY_REVOKE)) {
      z->keys[z->nkeys++] = i;
    }
  }
  return VS_SECURE;
}

/*
 * Denial of existence
 */

static ares_bool_t map_has(const unsigned char *map, size_t len,
                           unsigned short type)
{
  ares_bool_t bad;
  /* the maps are checked when collected */
  return ares_dnssec_bitmap_has(map, len, type, &bad);
}

/* The next name and type bit map of NSEC record 'idx' */
static void nsec_fields(const struct nsecs *ns, size_t idx,
                        unsigned char         next[DNSSEC_NAME_MAX],
                        const unsigned char **pmap, size_t *pmaplen)
{
  const struct dnssec_rr *rr  = &ns->m->rrs[ns->rr[idx]];
  const unsigned char    *d   = DNSSEC_RR_RDATA(ns->m, rr);
  size_t                  off = 0;
  /* the record was checked when collected */
  (void)ares_dnssec_read_name(d, rr->rdlen, &off, ARES_FALSE, next);
  *pmap    = d + off;
  *pmaplen = rr->rdlen - off;
}

/* The next hash, flags and type bit map of NSEC3 record 'idx' */
static void n3_fields(const struct nsecs *ns, size_t idx,
                      const unsigned char **pnext, unsigned char *pflags,
                      const unsigned char **pmap, size_t *pmaplen)
{
  const struct dnssec_rr *rr  = &ns->m->rrs[ns->rr[idx]];
  const unsigned char    *d   = DNSSEC_RR_RDATA(ns->m, rr);
  size_t                  off = 5 + (size_t)d[4] + 1;
  *pflags                     = d[1];
  *pnext                      = d + off;
  *pmap                       = d + off + DNSSEC_NSEC3_HASHLEN;
  *pmaplen                    = rr->rdlen - off - DNSSEC_NSEC3_HASHLEN;
}

/* Check the fields of an NSEC or NSEC3 record, and that it can be used
   together with the records already collected. */
static ares_bool_t nsec_check(struct nsecs *ns, const struct dnssec_rr *rr)
{
  const struct dnssec_msg *m     = ns->m;
  const unsigned char     *d     = DNSSEC_RR_RDATA(m, rr);
  const unsigned char     *owner = DNSSEC_RR_OWNER(m, rr);
  unsigned char            name[DNSSEC_NAME_MAX];
  unsigned char            hash[DNSSEC_NSEC3_HASHLEN];
  size_t                   off = 0;
  ares_bool_t              bad;

  if (rr->type == DNSSEC_TYPE_NSEC) {
    if (ares_dnssec_read_name(d, rr->rdlen, &off, ARES_FALSE, name)) {
      return ARES_FALSE;
    }
  } else {
    size_t saltlen;
    /* RFC 5155 8.1 and 8.2: ignore unknown hash algorithms and flags */
    if ((rr->rdlen < 6) || (d[0] != DNSSEC_NSEC3_SHA1) || (d[1] > 1)) {
      return ARES_FALSE;
    }
    saltlen = d[4];
    off     = 5 + saltlen + 1 + DNSSEC_NSEC3_HASHLEN;
    if ((off > rr->rdlen) || (d[5 + saltlen] != DNSSEC_NSEC3_HASHLEN)) {
      return ARES_FALSE;
    }
    /* the owner is the base32hex hash as a label below the zone */
    if ((ares_dnssec_name_labels(owner) !=
         ares_dnssec_name_labels(ns->zone) + 1) ||
        (owner[0] != 32) ||
        (ares_dnssec_b32hex_decode(&owner[1], 32, hash, sizeof(hash)) !=
         DNSSEC_NSEC3_HASHLEN)) {
      return ARES_FALSE;
    }
    /* RFC 5155 8.2: all records in a proof use the same parameters */
    if (ns->n && ((ns->iterations != rd16(&d[2])) || (ns->saltlen != saltlen) ||
                  (saltlen && memcmp(ns->salt, &d[5], saltlen)))) {
      return ARES_FALSE;
    }
    if (!ns->n) {
      ns->iterations = rd16(&d[2]);
      ns->saltlen    = (unsigned char)saltlen;
      ns->salt       = &d[5];
    }
  }
  (void)ares_dnssec_bitmap_has(d + off, rr->rdlen - off, 0, &bad);
  return !bad;
}

/* Collect and validate the NSEC or NSEC3 records in the authority section
   of 'm' that can prove something about 'sname'. They must all come from
   one zone: 'known' when the caller knows the zone that holds 'sname',
   otherwise the closest zone above 'sname' that signed any, or with
   'parent' set, the closest one strictly above it (for DS, which is in the
   parent zone). Without signed records, walk_down() decides if the
   response is insecure, unless 'known' is set. */
static vstat denial_collect(struct vctx *v, struct dnssec_msg *m,
                            const unsigned char *sname, ares_bool_t parent,
                            const unsigned char *known, struct nsecs *ns)
{
  struct dnssec_zone  *z;
  /* a DS denial is in the parent zone, validated with the anchors above */
  const unsigned char *ta =
    !parent ? deepest_anchor(v->ctx, sname)
            : (sname[0] ? deepest_anchor(v->ctx, sname + 1 + sname[0]) : NULL);
  unsigned int tlabels     = 0;
  ares_bool_t  have_signer = ARES_FALSE;
  ares_bool_t  self        = ARES_FALSE;
  size_t       i;
  vstat        r;

  memset(ns, 0, sizeof(*ns));
  ns->m   = m;
  ns->ttl = 0xffffffff;
  if (ta) {
    tlabels = ares_dnssec_name_labels(ta);
  }

  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    unsigned short          covered;
    struct dnssec_sig       s;
    if ((rr->section != DNSSEC_SECT_AUTHORITY) ||
        (rr->type != DNSSEC_TYPE_RRSIG) || (rr->rdlen < 18)) {
      continue;
    }
    covered = rd16(DNSSEC_RR_RDATA(m, rr));
    /* only zones at or below the closest trust anchor, see
       rrset_validate() */
    if (((covered != DNSSEC_TYPE_NSEC) && (covered != DNSSEC_TYPE_NSEC3)) ||
        !sig_parse(m, rr, &s) || !ta ||
        !ares_dnssec_name_sub(sname, s.signer) ||
        (ares_dnssec_name_labels(s.signer) < tlabels)) {
      continue;
    }
    if (parent && ares_dnssec_name_eq(sname, s.signer)) {
      self = ARES_TRUE;
      continue;
    }
    if (!have_signer || (ares_dnssec_name_labels(s.signer) >
                         ares_dnssec_name_labels(ns->zone))) {
      memcpy(ns->zone, s.signer, DNSSEC_NAME_MAX);
      have_signer = ARES_TRUE;
    }
  }

  if (!have_signer) {
    if (self) {
      why(v, "DS for %s is denied by the zone itself instead of its parent",
          NAMESTR(sname, v->nb[0]));
      return VS_BOGUS;
    }
    r = known ? VS_SECURE : walk_down(v, sname, NULL);
    if (r == VS_SECURE) {
      why(v, "no signed NSEC or NSEC3 records for %s",
          NAMESTR(sname, v->nb[0]));
      r = VS_BOGUS;
    }
    return r;
  }
  if (known && !ares_dnssec_name_eq(ns->zone, known)) {
    why(v, "denial of existence for %s is from %s instead of %s",
        NAMESTR(sname, v->nb[0]), NAMESTR(ns->zone, v->nb[1]),
        NAMESTR(known, v->nb[2]));
    return VS_BOGUS;
  }

  r = zone_keys(v, ns->zone, &z);
  if (r != VS_SECURE) {
    return r;
  }

  for (i = 0; (i < m->nrrs) && (ns->n < DNSSEC_MAX_DENIAL); i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    const unsigned char    *signer;
    unsigned int            labels;
    unsigned int            ttl;
    size_t                  j;
    if ((rr->section != DNSSEC_SECT_AUTHORITY) ||
        (rr->rclass != DNSSEC_CLASS_IN) ||
        ((rr->type != DNSSEC_TYPE_NSEC) && (rr->type != DNSSEC_TYPE_NSEC3)) ||
        !rrset_first(m, i) ||
        !ares_dnssec_name_sub(DNSSEC_RR_OWNER(m, rr), ns->zone) ||
        !rrset_signed_by(m, i, ns->zone)) {
      continue;
    }
    /* one kind only */
    if (ns->n && ((rr->type == DNSSEC_TYPE_NSEC3) != ns->nsec3)) {
      continue;
    }
    r = rrset_validate(v, m, i, &ttl, &labels, &signer);
    if (v->error) {
      return r;
    }
    if ((r != VS_SECURE) || !ares_dnssec_name_eq(signer, ns->zone) ||
        (labels != ares_dnssec_name_sig_labels(DNSSEC_RR_OWNER(m, rr)))) {
      continue;
    }
    for (j = i; (j < m->nrrs) && (ns->n < DNSSEC_MAX_DENIAL); j++) {
      if (!rr_same_set(m, &m->rrs[j], rr) || !nsec_check(ns, &m->rrs[j])) {
        continue;
      }
      ns->nsec3       = (rr->type == DNSSEC_TYPE_NSEC3);
      ns->rr[ns->n++] = j;
    }
    if (ttl < ns->ttl) {
      ns->ttl = ttl;
    }
  }
  if (!ns->n) {
    why(v, "no valid NSEC or NSEC3 records from %s",
        NAMESTR(ns->zone, v->nb[0]));
    return VS_BOGUS;
  }
  if (ns->nsec3 && (ns->iterations > DNSSEC_NSEC3_MAX_ITER)) {
    why(v, "NSEC3 records of %s use %u iterations, more than %u",
        NAMESTR(ns->zone, v->nb[0]), (unsigned int)ns->iterations,
        (unsigned int)DNSSEC_NSEC3_MAX_ITER);
    return VS_BOGUS;
  }
  return VS_SECURE;
}

static size_t nsec_match(const struct nsecs *ns, const unsigned char *name)
{
  size_t i;
  for (i = 0; i < ns->n; i++) {
    const struct dnssec_rr *rr = &ns->m->rrs[ns->rr[i]];
    if (ares_dnssec_name_eq(DNSSEC_RR_OWNER(ns->m, rr), name)) {
      return i;
    }
  }
  return DNSSEC_NONE;
}

/* Find an NSEC that covers 'name', meaning 'name' is between its owner
   and next names. Sets 'next' to the next name. */
static size_t nsec_cover(const struct nsecs *ns, const unsigned char *name,
                         unsigned char next[DNSSEC_NAME_MAX])
{
  size_t i;
  if (!ares_dnssec_name_sub(name, ns->zone)) {
    return DNSSEC_NONE;
  }
  for (i = 0; i < ns->n; i++) {
    const unsigned char *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
    const unsigned char *map;
    size_t               maplen;
    nsec_fields(ns, i, next, &map, &maplen);
    if (ares_dnssec_name_cmp(owner, name) >= 0) {
      continue;
    }
    /* the last NSEC in a zone has the apex as next name */
    if ((ares_dnssec_name_cmp(owner, next) < 0) &&
        (ares_dnssec_name_cmp(name, next) >= 0)) {
      continue;
    }
    /* RFC 6840 4.1: an NSEC at a delegation or DNAME says nothing about
       the names below it */
    if (ares_dnssec_name_sub(name, owner) &&
        ((map_has(map, maplen, DNSSEC_TYPE_NS) &&
          !map_has(map, maplen, DNSSEC_TYPE_SOA)) ||
         map_has(map, maplen, DNSSEC_TYPE_DNAME))) {
      continue;
    }
    return i;
  }
  return DNSSEC_NONE;
}

/* The number of labels of the closest encloser of 'name' that an NSEC
   covering it proves */
static unsigned int nsec_ce_labels(const unsigned char *name,
                                   const unsigned char *owner,
                                   const unsigned char *next)
{
  unsigned int a = ares_dnssec_name_common(name, owner);
  unsigned int b = ares_dnssec_name_common(name, next);
  return (a > b) ? a : b;
}

/* Make the wildcard name at the closest encloser of 'name' */
static ares_bool_t wildcard_name(unsigned char        out[DNSSEC_NAME_MAX],
                                 const unsigned char *name,
                                 unsigned int         ce_labels)
{
  const unsigned char *ce  = ares_dnssec_name_suffix(name, ce_labels);
  size_t               len = ares_dnssec_name_len(ce);
  if (len + 2 > DNSSEC_NAME_MAX) {
    return ARES_FALSE;
  }
  out[0] = 1;
  out[1] = '*';
  memcpy(&out[2], ce, len);
  return ARES_TRUE;
}

/* A type bit map in a matching record proves that 'qtype' does not exist
   at the name. RFC 4035 5.4, RFC 5155 8.5 and 8.6, RFC 6840 4.1 and
   4.3. */
static vstat map_nodata(struct vctx *v, const unsigned char *map, size_t maplen,
                        const unsigned char *sname, unsigned short qtype)
{
  char        tbuf[16];
  ares_bool_t ns  = map_has(map, maplen, DNSSEC_TYPE_NS);
  ares_bool_t soa = map_has(map, maplen, DNSSEC_TYPE_SOA);
  if (map_has(map, maplen, qtype) || map_has(map, maplen, DNSSEC_TYPE_CNAME)) {
    why(v, "denial of existence for %s %s says it exists",
        NAMESTR(sname, v->nb[0]), typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_BOGUS;
  }
  if (qtype == DNSSEC_TYPE_DS) {
    /* DS is in the parent zone, the child's apex record does not know */
    if (soa && sname[0]) {
      why(v, "denial of DS for %s is from the child zone",
          NAMESTR(sname, v->nb[0]));
      return VS_BOGUS;
    }
  } else if (ns && !soa) {
    /* the parent side of a delegation only knows about DS */
    why(v, "denial of existence for %s %s is from the parent zone",
        NAMESTR(sname, v->nb[0]), typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

static vstat nsec_nodata(struct vctx *v, const struct nsecs *ns,
                         const unsigned char *sname, unsigned short qtype,
                         ares_bool_t *pnx)
{
  unsigned char        next[DNSSEC_NAME_MAX];
  unsigned char        wc[DNSSEC_NAME_MAX];
  const unsigned char *map;
  size_t               maplen;
  size_t               i;

  i = nsec_match(ns, sname);
  if (i != DNSSEC_NONE) {
    nsec_fields(ns, i, next, &map, &maplen);
    /* compact denial of existence, RFC 9824 */
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *pnx = ARES_TRUE;
      return VS_SECURE;
    }
    return map_nodata(v, map, maplen, sname, qtype);
  }
  i = nsec_cover(ns, sname, next);
  if (i != DNSSEC_NONE) {
    const unsigned char *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
    unsigned int         ce;
    /* an empty non-terminal: the next name is below sname */
    if (ares_dnssec_name_sub(next, sname) &&
        !ares_dnssec_name_eq(next, sname)) {
      return VS_SECURE;
    }
    /* sname does not exist, a wildcard at the closest encloser without
       the type makes this NODATA, RFC 4035 3.1.3.4 */
    ce = nsec_ce_labels(sname, owner, next);
    if ((ce >= ares_dnssec_name_labels(ns->zone)) &&
        wildcard_name(wc, sname, ce)) {
      i = nsec_match(ns, wc);
      if (i != DNSSEC_NONE) {
        nsec_fields(ns, i, next, &map, &maplen);
        return map_nodata(v, map, maplen, sname, qtype);
      }
    }
  }
  why(v, "no NSEC proves NODATA for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

static vstat nsec_nxdomain(struct vctx *v, const struct nsecs *ns,
                           const unsigned char *sname)
{
  unsigned char        next[DNSSEC_NAME_MAX];
  unsigned char        wc[DNSSEC_NAME_MAX];
  const unsigned char *owner;
  const unsigned char *map;
  size_t               maplen;
  unsigned int         ce;
  size_t               i;

  i = nsec_match(ns, sname);
  if (i != DNSSEC_NONE) {
    nsec_fields(ns, i, next, &map, &maplen);
    /* compact denial of existence with the NXDOMAIN rcode restored,
       RFC 9824 section 5.1 */
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      return VS_SECURE;
    }
    why(v, "NSEC says %s exists", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  i = nsec_cover(ns, sname, next);
  if (i == DNSSEC_NONE) {
    why(v, "no NSEC proves %s does not exist", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  if (ares_dnssec_name_sub(next, sname)) {
    why(v, "NSEC says %s is an empty non-terminal", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
  ce    = nsec_ce_labels(sname, owner, next);
  if ((ce < ares_dnssec_name_labels(ns->zone)) ||
      !wildcard_name(wc, sname, ce) ||
      (nsec_cover(ns, wc, next) == DNSSEC_NONE)) {
    why(v, "no NSEC proves there is no wildcard for %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

/* A wildcard answer, synthesized from the wildcard with 'labels' labels
   after the '*': sname must not exist, and the wildcard must be at its
   closest encloser. RFC 4035 5.3.4. */
static vstat nsec_wildcard(struct vctx *v, const struct nsecs *ns,
                           const unsigned char *sname, unsigned int labels)
{
  unsigned char next[DNSSEC_NAME_MAX];
  size_t        i = nsec_cover(ns, sname, next);
  if ((i == DNSSEC_NONE) || ares_dnssec_name_sub(next, sname) ||
      (nsec_ce_labels(sname, DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]),
                      next) != labels)) {
    why(v, "no NSEC proves the wildcard expansion of %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

static vstat nsec_ds(struct vctx *v, const struct nsecs *ns,
                     const unsigned char *name, dsfact *fact)
{
  unsigned char        next[DNSSEC_NAME_MAX];
  const unsigned char *map;
  size_t               maplen;
  size_t               i;

  i = nsec_match(ns, name);
  if (i != DNSSEC_NONE) {
    vstat r;
    nsec_fields(ns, i, next, &map, &maplen);
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *fact = DS_NO_NAME;
      return VS_SECURE;
    }
    r = map_nodata(v, map, maplen, name, DNSSEC_TYPE_DS);
    if (r == VS_SECURE) {
      *fact =
        map_has(map, maplen, DNSSEC_TYPE_NS) ? DS_UNSIGNED_CUT : DS_NOT_CUT;
    }
    return r;
  }
  i = nsec_cover(ns, name, next);
  if (i != DNSSEC_NONE) {
    /* an empty non-terminal, or no name at all */
    *fact = ares_dnssec_name_sub(next, name) ? DS_NOT_CUT : DS_NO_NAME;
    return VS_SECURE;
  }
  why(v, "no NSEC proves the absence of DS for %s", NAMESTR(name, v->nb[0]));
  return VS_BOGUS;
}

/*
 * NSEC3, RFC 5155
 */

static vstat n3_hash(struct vctx *v, const struct nsecs *ns,
                     const unsigned char *name,
                     unsigned char        hash[DNSSEC_NSEC3_HASHLEN])
{
  unsigned char lower[DNSSEC_NAME_MAX];
  v->ctx->nhash += (unsigned long)ns->iterations + 1;
  if (v->ctx->nhash > DNSSEC_MAX_NSEC3_WORK) {
    why(v, "too many NSEC3 hash calculations");
    return VS_INDETERMINATE;
  }
  ares_dnssec_name_lower(lower, name);
  if (ares_dnssec_nsec3_hash(&v->ctx->crypto, lower,
                             ares_dnssec_name_len(lower), ns->salt, ns->saltlen,
                             ns->iterations, hash)) {
    why(v, "NSEC3 hash calculation failed");
    return VS_INDETERMINATE;
  }
  return VS_SECURE;
}

static void n3_owner(const struct nsecs *ns, size_t idx,
                     unsigned char hash[DNSSEC_NSEC3_HASHLEN])
{
  const unsigned char *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[idx]]);
  /* checked when collected */
  (void)ares_dnssec_b32hex_decode(&owner[1], owner[0], hash,
                                  DNSSEC_NSEC3_HASHLEN);
}

static size_t n3_match(const struct nsecs *ns, const unsigned char *hash)
{
  size_t i;
  for (i = 0; i < ns->n; i++) {
    unsigned char oh[DNSSEC_NSEC3_HASHLEN];
    n3_owner(ns, i, oh);
    if (!memcmp(oh, hash, DNSSEC_NSEC3_HASHLEN)) {
      return i;
    }
  }
  return DNSSEC_NONE;
}

static size_t n3_cover(const struct nsecs *ns, const unsigned char *hash)
{
  size_t i;
  for (i = 0; i < ns->n; i++) {
    unsigned char        oh[DNSSEC_NSEC3_HASHLEN];
    const unsigned char *next;
    const unsigned char *map;
    size_t               maplen;
    unsigned char        flags;
    n3_owner(ns, i, oh);
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if (memcmp(oh, next, DNSSEC_NSEC3_HASHLEN) < 0) {
      if ((memcmp(oh, hash, DNSSEC_NSEC3_HASHLEN) < 0) &&
          (memcmp(hash, next, DNSSEC_NSEC3_HASHLEN) < 0)) {
        return i;
      }
    }
    /* the last one in the hash order wraps around */
    else if ((memcmp(hash, oh, DNSSEC_NSEC3_HASHLEN) > 0) ||
             (memcmp(hash, next, DNSSEC_NSEC3_HASHLEN) < 0)) {
      return i;
    }
  }
  return DNSSEC_NONE;
}

/* The closest encloser proof, RFC 5155 section 8.3. When there is an NSEC3
   matching sname itself, sets *pmatch to it and returns. Otherwise sets
   the label count of the closest encloser and if the NSEC3 covering the
   next closer name has the opt-out flag. */
static vstat n3_closest_encloser(struct vctx *v, const struct nsecs *ns,
                                 const unsigned char *sname, size_t *pmatch,
                                 unsigned int *pce, ares_bool_t *poptout)
{
  unsigned char hash[DNSSEC_NSEC3_HASHLEN];
  unsigned char prev[DNSSEC_NSEC3_HASHLEN];
  unsigned int  zl = ares_dnssec_name_labels(ns->zone);
  unsigned int  sl = ares_dnssec_name_labels(sname);
  unsigned int  l;

  *pmatch = DNSSEC_NONE;
  if (!ares_dnssec_name_sub(sname, ns->zone)) {
    why(v, "NSEC3 records are not from a zone above %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  for (l = sl; l >= zl; l--) {
    const unsigned char *map;
    const unsigned char *next;
    size_t               maplen;
    unsigned char        flags;
    size_t               i;
    vstat r = n3_hash(v, ns, ares_dnssec_name_suffix(sname, l), hash);
    if (r != VS_SECURE) {
      return r;
    }
    i = n3_match(ns, hash);
    if (i != DNSSEC_NONE) {
      if (l == sl) {
        *pmatch = i;
        return VS_SECURE;
      }
      n3_fields(ns, i, &next, &flags, &map, &maplen);
      if (map_has(map, maplen, DNSSEC_TYPE_DNAME) ||
          (map_has(map, maplen, DNSSEC_TYPE_NS) &&
           !map_has(map, maplen, DNSSEC_TYPE_SOA))) {
        why(v, "NSEC3 closest encloser of %s is a delegation or DNAME",
            NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      i = n3_cover(ns, prev);
      if (i == DNSSEC_NONE) {
        why(v, "no NSEC3 covers the next closer name of %s",
            NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      n3_fields(ns, i, &next, &flags, &map, &maplen);
      *pce     = l;
      *poptout = !!(flags & DNSSEC_NSEC3_OPTOUT);
      return VS_SECURE;
    }
    memcpy(prev, hash, sizeof(prev));
    if (!l) {
      break;
    }
  }
  why(v, "no NSEC3 closest encloser proof for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

/* Is the wildcard at the closest encloser covered (nonexistent) or
   matched? Returns the record index or DNSSEC_NONE. */
static vstat n3_wildcard_find(struct vctx *v, const struct nsecs *ns,
                              const unsigned char *sname, unsigned int ce,
                              ares_bool_t cover, size_t *pidx)
{
  unsigned char wc[DNSSEC_NAME_MAX];
  unsigned char hash[DNSSEC_NSEC3_HASHLEN];
  vstat         r;
  *pidx = DNSSEC_NONE;
  if (!wildcard_name(wc, sname, ce)) {
    return VS_SECURE;
  }
  r = n3_hash(v, ns, wc, hash);
  if (r == VS_SECURE) {
    *pidx = cover ? n3_cover(ns, hash) : n3_match(ns, hash);
  }
  return r;
}

/* RFC 5155 8.4 */
static vstat n3_nxdomain(struct vctx *v, const struct nsecs *ns,
                         const unsigned char *sname)
{
  unsigned int ce     = 0;
  ares_bool_t  optout = ARES_FALSE;
  size_t       i;
  vstat        r = n3_closest_encloser(v, ns, sname, &i, &ce, &optout);
  if (r != VS_SECURE) {
    return r;
  }
  if (i != DNSSEC_NONE) {
    const unsigned char *next;
    const unsigned char *map;
    size_t               maplen;
    unsigned char        flags;
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    /* compact denial of existence, RFC 9824 section 5.1 */
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      return VS_SECURE;
    }
    why(v, "NSEC3 says %s exists", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  r = n3_wildcard_find(v, ns, sname, ce, ARES_TRUE, &i);
  if (r != VS_SECURE) {
    return r;
  }
  if (i == DNSSEC_NONE) {
    why(v, "no NSEC3 proves there is no wildcard for %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  if (optout) {
    /* RFC 5155 12.2: names in an opt-out span may be unsigned
       delegations */
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  return VS_SECURE;
}

/* RFC 5155 8.5, 8.6 and 8.7 */
static vstat n3_nodata(struct vctx *v, const struct nsecs *ns,
                       const unsigned char *sname, unsigned short qtype,
                       ares_bool_t *pnx)
{
  const unsigned char *next;
  const unsigned char *map;
  size_t               maplen;
  unsigned char        flags;
  unsigned int         ce     = 0;
  ares_bool_t          optout = ARES_FALSE;
  size_t               i;
  vstat                r = n3_closest_encloser(v, ns, sname, &i, &ce, &optout);
  if (r != VS_SECURE) {
    return r;
  }
  if (i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *pnx = ARES_TRUE;
      return VS_SECURE;
    }
    return map_nodata(v, map, maplen, sname, qtype);
  }
  /* a wildcard NODATA response */
  r = n3_wildcard_find(v, ns, sname, ce, ARES_FALSE, &i);
  if (r != VS_SECURE) {
    return r;
  }
  if (i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    r = map_nodata(v, map, maplen, sname, qtype);
    if ((r == VS_SECURE) && optout) {
      why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
      r = VS_INSECURE;
    }
    return r;
  }
  if (optout) {
    /* an unsigned delegation (or no name) in an opt-out span */
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  why(v, "no NSEC3 proves NODATA for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

/* RFC 5155 8.8 */
static vstat n3_wildcard(struct vctx *v, const struct nsecs *ns,
                         const unsigned char *sname, unsigned int labels)
{
  unsigned char        hash[DNSSEC_NSEC3_HASHLEN];
  const unsigned char *next;
  const unsigned char *map;
  size_t               maplen;
  unsigned char        flags;
  size_t               i;
  vstat                r;

  if ((labels < ares_dnssec_name_labels(ns->zone)) ||
      (labels >= ares_dnssec_name_labels(sname))) {
    why(v, "bad wildcard expansion of %s", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  r = n3_hash(v, ns, ares_dnssec_name_suffix(sname, labels + 1), hash);
  if (r != VS_SECURE) {
    return r;
  }
  i = n3_cover(ns, hash);
  if (i == DNSSEC_NONE) {
    why(v, "no NSEC3 proves the wildcard expansion of %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  n3_fields(ns, i, &next, &flags, &map, &maplen);
  if (flags & DNSSEC_NSEC3_OPTOUT) {
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  return VS_SECURE;
}

static vstat n3_ds(struct vctx *v, const struct nsecs *ns,
                   const unsigned char *name, dsfact *fact)
{
  const unsigned char *next;
  const unsigned char *map;
  size_t               maplen;
  unsigned char        flags;
  unsigned int         ce     = 0;
  ares_bool_t          optout = ARES_FALSE;
  size_t               i;
  vstat                r = n3_closest_encloser(v, ns, name, &i, &ce, &optout);
  if (r != VS_SECURE) {
    return r;
  }
  if (i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if (map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *fact = DS_NO_NAME;
      return VS_SECURE;
    }
    r = map_nodata(v, map, maplen, name, DNSSEC_TYPE_DS);
    if (r == VS_SECURE) {
      *fact =
        map_has(map, maplen, DNSSEC_TYPE_NS) ? DS_UNSIGNED_CUT : DS_NOT_CUT;
    }
    return r;
  }
  /* RFC 5155 8.6: without a matching NSEC3, only an opt-out span can hold
     an unsigned delegation */
  *fact = optout ? DS_OPTOUT : DS_NO_NAME;
  return VS_SECURE;
}

/* What does the response 'm' to a DS query for 'name' prove, when it has
   no DS records? The proof must come from 'parent', the zone above
   'name'. */
static vstat ds_denial(struct vctx *v, struct dnssec_msg *m,
                       const unsigned char *name, const unsigned char *parent,
                       dsfact *fact)
{
  struct nsecs ns;
  vstat        r = denial_collect(v, m, name, ARES_TRUE, parent, &ns);
  if (r != VS_SECURE) {
    return r;
  }
  return ns.nsec3 ? n3_ds(v, &ns, name, fact) : nsec_ds(v, &ns, name, fact);
}

/* Find the validated DS RRset of 'zone', RFC 4035 section 5.2 */
static vstat ds_lookup(struct vctx *v, const unsigned char *zone,
                       struct dnssec_msg **pdm, size_t *pfirst)
{
  struct dnssec_msg   *m;
  const unsigned char *signer;
  unsigned int         labels;
  unsigned int         ttl;
  size_t               first;
  vstat                r = query_get(v, zone, DNSSEC_TYPE_DS, &m);
  if (r != VS_SECURE) {
    return r;
  }

  first = rrset_find(m, DNSSEC_SECT_ANSWER, zone, DNSSEC_TYPE_DS);
  if (first != DNSSEC_NONE) {
    r = rrset_validate(v, m, first, &ttl, &labels, &signer);
    if ((r == VS_SECURE) && (labels != ares_dnssec_name_sig_labels(zone))) {
      why(v, "DS RRSIG for %s has a bad label count", NAMESTR(zone, v->nb[0]));
      r = VS_BOGUS;
    }
    *pdm    = m;
    *pfirst = first;
    return r;
  }

  /* No DS records: 'zone' must be proven an unsigned delegation, by its
     parent zone. Which zone that is only a walk from the top shows. */
  r = walk_down(v, zone, NULL);
  if (r == VS_SECURE) {
    /* an RRSIG claims 'zone' is a zone, but its parent says it is not */
    why(v, "%s signs records but is no delegation", NAMESTR(zone, v->nb[0]));
    r = VS_BOGUS;
  }
  return r;
}

/* Get the validated keys of 'zone' */
static vstat zone_keys(struct vctx *v, const unsigned char *zone,
                       struct dnssec_zone **pz)
{
  ares_dnssec_ctx_t  *ctx    = v->ctx;
  struct dnssec_zone *z      = zone_find(ctx, zone);
  struct dnssec_msg  *km     = NULL;
  struct dnssec_msg  *dm     = NULL;
  size_t              dfirst = DNSSEC_NONE;
  ares_bool_t         by_anchor;
  unsigned int        i;
  vstat               rk;
  vstat               r;

  *pz = z;
  if (z) {
    if (z->status != VS_SECURE) {
      why(v, "%s", z->reason);
    }
    return z->status;
  }
  for (i = 0; i < v->nactive; i++) {
    if (ares_dnssec_name_eq(v->active[i], zone)) {
      /* the keys of 'zone' depend on themselves */
      why(v, "loop in the chain of trust at %s", NAMESTR(zone, v->nb[0]));
      return VS_BOGUS;
    }
  }
  if ((v->depth >= DNSSEC_MAX_DEPTH) ||
      (v->nactive >= (sizeof(v->active) / sizeof(v->active[0])))) {
    why(v, "chain of trust too long");
    return VS_INDETERMINATE;
  }
  v->depth++;
  v->active[v->nactive++] = zone;

  by_anchor = anchored(ctx, zone);
  if (!by_anchor && !covered(ctx, zone)) {
    /* RFC 4035 section 4.3: without a trust anchor, nothing is known */
    why(v, "no trust anchor for %s", NAMESTR(zone, v->nb[0]));
    r = VS_INDETERMINATE;
    goto done;
  }
  /* ask for the DNSKEY and DS records at the same time */
  rk = query_get(v, zone, DNSSEC_TYPE_DNSKEY, &km);
  if (!by_anchor) {
    r = ds_lookup(v, zone, &dm, &dfirst);
    if (r != VS_SECURE) {
      goto done;
    }
  }
  r = rk;
  if (r != VS_SECURE) {
    goto done;
  }

  z = ares_malloc_zero(sizeof(*z));
  if (!z) {
    r = vs_oom(v);
    goto done;
  }
  ares_dnssec_name_lower(z->name, zone);
  r = dnskey_validate(v, z, km, dm, dfirst, by_anchor);

done:
  v->depth--;
  v->nactive--;
  if ((r == VS_PENDING) || v->error) {
    ares_free(z);
    return r;
  }
  if (!z) {
    z = ares_malloc_zero(sizeof(*z));
    if (!z) {
      return vs_oom(v);
    }
    ares_dnssec_name_lower(z->name, zone);
  }
  z->status = r;
  if (r != VS_SECURE) {
    ares_strcpy(z->reason, v->reason, sizeof(z->reason));
  }
  z->next    = ctx->zones;
  ctx->zones = z;
  *pz        = z;
  return r;
}

static vstat walk_down_labels(struct vctx *v, const unsigned char *name,
                              unsigned char *zone)
{
  ares_dnssec_ctx_t   *ctx = v->ctx;
  const unsigned char *ta  = deepest_anchor(ctx, name);
  unsigned char        cur[DNSSEC_NAME_MAX];
  struct dnssec_zone  *z;
  unsigned int         nl = ares_dnssec_name_labels(name);
  unsigned int         l;
  vstat                r;

  if (!ta) {
    why(v, "no trust anchor for %s", NAMESTR(name, v->nb[0]));
    return VS_INDETERMINATE;
  }
  memcpy(cur, ta, ares_dnssec_name_len(ta));
  r = zone_keys(v, cur, &z);
  if (r != VS_SECURE) {
    return r;
  }

  /* ask for all the DS records at once */
  for (l = ares_dnssec_name_labels(cur) + 1; l <= nl; l++) {
    struct dnssec_msg *m;
    (void)query_get(v, ares_dnssec_name_suffix(name, l), DNSSEC_TYPE_DS, &m);
    if (v->error) {
      return VS_INDETERMINATE;
    }
  }

  for (l = ares_dnssec_name_labels(cur) + 1; l <= nl; l++) {
    const unsigned char *n = ares_dnssec_name_suffix(name, l);
    struct dnssec_query *q;
    struct dnssec_msg   *m;
    const unsigned char *signer;
    unsigned int         labels;
    unsigned int         ttl;
    size_t               first;
    unsigned char        parent;
    dsfact               fact = DS_NO_NAME;

    r = query_get(v, n, DNSSEC_TYPE_DS, &m);
    if (r != VS_SECURE) {
      return r;
    }

    first = rrset_find(m, DNSSEC_SECT_ANSWER, n, DNSSEC_TYPE_DS);
    if (first == DNSSEC_NONE) {
      first = rrset_find(m, DNSSEC_SECT_ANSWER, n, DNSSEC_TYPE_CNAME);
    }
    if (first != DNSSEC_NONE) {
      /* A delegation with DS records, or an alias. Either way the records
         belong to the zone we are in. */
      if (!rrset_signed_by(m, first, cur)) {
        why(v, "%s %s is not signed by %s", NAMESTR(n, v->nb[0]),
            (m->rrs[first].type == DNSSEC_TYPE_DS) ? "DS" : "CNAME",
            NAMESTR(cur, v->nb[2]));
        return VS_BOGUS;
      }
      if (m->rrs[first].type == DNSSEC_TYPE_CNAME) {
        /* with the proof, when it is a wildcard expansion */
        ttl = 0xffffffff;
        r   = answer_rrset(v, m, first, cur, &ttl);
        if (r != VS_SECURE) {
          return r;
        }
        continue;
      }
      r = rrset_validate(v, m, first, &ttl, &labels, &signer);
      if (r != VS_SECURE) {
        return r;
      }
      r = zone_keys(v, n, &z);
      if (r != VS_SECURE) {
        return r;
      }
      memcpy(cur, n, ares_dnssec_name_len(n));
      continue;
    }

    /* The proof is the same every run, remember it. It depends on the
       zone above, so remember that too. */
    q      = query_find(ctx, n, DNSSEC_TYPE_DS);
    parent = (unsigned char)(ares_dnssec_name_labels(cur) + 1);
    if (q && (q->wstat == VS_SECURE) && (q->wparent == parent)) {
      fact = (dsfact)q->wfact;
    } else {
      r = ds_denial(v, m, n, cur, &fact);
      if (r != VS_SECURE) {
        return r;
      }
      if (q) {
        q->wstat   = VS_SECURE;
        q->wfact   = (unsigned char)fact;
        q->wparent = parent;
      }
    }
    switch (fact) {
      case DS_UNSIGNED_CUT:
        why(v, "%s is an unsigned delegation", NAMESTR(n, v->nb[0]));
        return VS_INSECURE;
      case DS_OPTOUT:
        why(v, "%s is in an NSEC3 opt-out span", NAMESTR(n, v->nb[0]));
        return VS_INSECURE;
      case DS_NO_NAME:
        /* nothing below exists, it is all in the secure zone 'cur' */
        l = nl;
        break;
      default:
        break;
    }
  }
  if (zone) {
    memcpy(zone, cur, ares_dnssec_name_len(cur));
  }
  return VS_SECURE;
}

/* Find the security status of the zone 'name' is in, starting at the
   closest trust anchor and walking down one label at a time, asking for
   the DS records at each name (RFC 4035 section 5.2, RFC 6840 section 4.4).
   Returns VS_INSECURE when there is a proven unsigned delegation above
   'name', and VS_SECURE when 'name' is in a secure zone, where all data
   must be signed. That zone is then copied to 'zone', if not NULL. */
static vstat walk_down(struct vctx *v, const unsigned char *name,
                       unsigned char *zone)
{
  vstat r;
  /* walk_down() and zone_keys() can call each other, through the proofs
     they need */
  if (v->depth >= DNSSEC_MAX_DEPTH) {
    why(v, "chain of trust too long");
    return VS_INDETERMINATE;
  }
  v->depth++;
  r = walk_down_labels(v, name, zone);
  v->depth--;
  return r;
}

/*
 * Answers
 */

/* Validate an answer RRset and, for a wildcard expansion, the proof that
   the wildcard applies. 'known' is the zone that holds it, if known. */
static vstat answer_rrset(struct vctx *v, struct dnssec_msg *m, size_t first,
                          const unsigned char *known, unsigned int *pttl)
{
  const unsigned char *owner = DNSSEC_RR_OWNER(m, &m->rrs[first]);
  const unsigned char *signer;
  unsigned int         labels;
  unsigned int         ttl;
  vstat                r = rrset_validate(v, m, first, &ttl, &labels, &signer);

  if ((r == VS_SECURE) && (labels < ares_dnssec_name_sig_labels(owner))) {
    /* expanded from a wildcard, RFC 4035 5.3.4 and RFC 5155 8.8 */
    struct nsecs ns;
    r = denial_collect(v, m, owner, ARES_FALSE, known, &ns);
    if (r == VS_SECURE) {
      if (!ares_dnssec_name_eq(ns.zone, signer)) {
        why(v, "the wildcard proof for %s is from another zone",
            NAMESTR(owner, v->nb[0]));
        r = VS_BOGUS;
      } else if (ns.nsec3) {
        r = n3_wildcard(v, &ns, owner, labels);
      } else {
        r = nsec_wildcard(v, &ns, owner, labels);
      }
      if (ns.ttl < ttl) {
        ttl = ns.ttl;
      }
    }
  }
  if (ttl < *pttl) {
    *pttl = ttl;
  }
  return r;
}

/* The negative caching TTL of a response, RFC 2308 section 5 */
static unsigned int negative_ttl(const struct dnssec_msg *m)
{
  size_t i;
  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    unsigned char           name[DNSSEC_NAME_MAX];
    size_t                  off = rr->rdata;
    unsigned int            minimum;
    if ((rr->section != DNSSEC_SECT_AUTHORITY) ||
        (rr->type != DNSSEC_TYPE_SOA)) {
      continue;
    }
    /* MNAME, RNAME, then serial, refresh, retry, expire and minimum */
    if (ares_dnssec_read_name(m->buf, m->len, &off, ARES_TRUE, name) ||
        ares_dnssec_read_name(m->buf, m->len, &off, ARES_TRUE, name) ||
        (off + 20 != (size_t)rr->rdata + rr->rdlen)) {
      return 0;
    }
    minimum = rd32(&m->buf[off + 16]);
    return (minimum < rr->ttl) ? minimum : rr->ttl;
  }
  return 0;
}

/* Validate the response to a query for a name that has no records of the
   type: NXDOMAIN or NODATA */
static vstat answer_negative(struct vctx *v, struct dnssec_msg *m,
                             const unsigned char *sname, unsigned short qtype,
                             unsigned int *pttl)
{
  ares_dnssec_req_t *req = v->req;
  struct nsecs       ns;
  ares_bool_t        nx = (m->rcode == DNSSEC_RCODE_NXDOMAIN);
  vstat r = denial_collect(v, m, sname, (qtype == DNSSEC_TYPE_DS), NULL, &ns);
  unsigned int ttl = negative_ttl(m);

  req->rcode = m->rcode;
  if (ttl < *pttl) {
    *pttl = ttl;
  }
  if (r != VS_SECURE) {
    return r;
  }
  if (nx) {
    r = ns.nsec3 ? n3_nxdomain(v, &ns, sname) : nsec_nxdomain(v, &ns, sname);
  } else {
    r = ns.nsec3 ? n3_nodata(v, &ns, sname, qtype, &nx)
                 : nsec_nodata(v, &ns, sname, qtype, &nx);
  }
  if (nx) {
    req->rcode = DNSSEC_RCODE_NXDOMAIN;
  }
  if (ns.ttl < *pttl) {
    *pttl = ns.ttl;
  }
  return r;
}

static vstat vs_combine(vstat a, vstat b)
{
  if ((a == VS_BOGUS) || (b == VS_BOGUS)) {
    return VS_BOGUS;
  }
  if ((a == VS_INDETERMINATE) || (b == VS_INDETERMINATE)) {
    return VS_INDETERMINATE;
  }
  if ((a == VS_INSECURE) || (b == VS_INSECURE)) {
    return VS_INSECURE;
  }
  return VS_SECURE;
}

static ares_bool_t authority_has_denial(const struct dnssec_msg *m)
{
  size_t i;
  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    if ((rr->section == DNSSEC_SECT_AUTHORITY) &&
        ((rr->type == DNSSEC_TYPE_SOA) || (rr->type == DNSSEC_TYPE_NSEC) ||
         (rr->type == DNSSEC_TYPE_NSEC3))) {
      return ARES_TRUE;
    }
  }
  return ARES_FALSE;
}

/* Find the DNAME RRset in the answer section that applies to 'sname', the
   one closest to the root: there are no names below a DNAME */
static size_t find_dname(const struct dnssec_msg *m, const unsigned char *sname)
{
  size_t found = DNSSEC_NONE;
  size_t i;
  for (i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr    = &m->rrs[i];
    const unsigned char    *owner = DNSSEC_RR_OWNER(m, rr);
    if ((rr->section == DNSSEC_SECT_ANSWER) &&
        (rr->type == DNSSEC_TYPE_DNAME) && (rr->rclass == DNSSEC_CLASS_IN) &&
        ares_dnssec_name_sub(sname, owner) &&
        !ares_dnssec_name_eq(sname, owner) &&
        ((found == DNSSEC_NONE) ||
         (ares_dnssec_name_labels(owner) <
          ares_dnssec_name_labels(DNSSEC_RR_OWNER(m, &m->rrs[found]))))) {
      found = i;
    }
  }
  return found;
}

/* The name 'sname' becomes with the DNAME record 'rr' (RFC 6672 section
   2.2), in 'out'. ARES_FALSE if the record is bad or the name too long. */
static ares_bool_t dname_subst(const struct dnssec_msg *m,
                               const struct dnssec_rr  *rr,
                               const unsigned char     *sname,
                               unsigned char            out[DNSSEC_NAME_MAX])
{
  unsigned char        target[DNSSEC_NAME_MAX];
  const unsigned char *owner = DNSSEC_RR_OWNER(m, rr);
  unsigned int         prefix =
    ares_dnssec_name_labels(sname) - ares_dnssec_name_labels(owner);
  size_t plen = 0;
  size_t off  = 0;
  /* the DNAME target is never compressed, RFC 6672 section 2.5 */
  if (ares_dnssec_read_name(DNSSEC_RR_RDATA(m, rr), rr->rdlen, &off, ARES_FALSE,
                            target) ||
      (off != rr->rdlen)) {
    return ARES_FALSE;
  }
  while (prefix--) {
    plen += 1 + (size_t)sname[plen];
  }
  if (plen + ares_dnssec_name_len(target) > DNSSEC_NAME_MAX) {
    return ARES_FALSE;
  }
  memmove(out, sname, plen);
  memcpy(&out[plen], target, ares_dnssec_name_len(target));
  return ARES_TRUE;
}

/* Read the target of the CNAME record 'rr' */
static ares_bool_t cname_target(const struct dnssec_msg *m,
                                const struct dnssec_rr  *rr,
                                unsigned char            out[DNSSEC_NAME_MAX])
{
  size_t off = rr->rdata;
  return !ares_dnssec_read_name(m->buf, m->len, &off, ARES_TRUE, out) &&
         (off == (size_t)rr->rdata + rr->rdlen);
}

/* Validate the answer to the request's question, following CNAME and
   DNAME records (RFC 6672) */
static vstat req_eval(struct vctx *v)
{
  ares_dnssec_req_t *req = v->req;
  unsigned char      sname[DNSSEC_NAME_MAX];
  unsigned char      next[DNSSEC_NAME_MAX];
  struct dnssec_msg *m;
  vstat              total = VS_SECURE;
  unsigned int       ttl   = 0xffffffff;
  unsigned int       hops  = 0;
  vstat              r;

  memcpy(sname, req->qname, DNSSEC_NAME_MAX);
  req->amsg   = NULL;
  req->nchain = 0;
  r           = query_get(v, sname, req->qtype, &m);
  if (r != VS_SECURE) {
    return r;
  }
  req->rcode = m->rcode;

  for (;;) {
    size_t first = find_dname(m, sname);

    if (first != DNSSEC_NONE) {
      /* A DNAME above sname applies. The CNAME record synthesized from it
         is not signed, the substitution is done here instead. */
      if (!dname_subst(m, &m->rrs[first], sname, next)) {
        why(v, "bad DNAME substitution for %s", NAMESTR(sname, v->nb[0]));
        total = VS_BOGUS;
        break;
      }
      r = answer_rrset(v, m, first, NULL, &ttl);
      if (r == VS_PENDING) {
        return r;
      }
      total = vs_combine(total, r);
      if ((total == VS_BOGUS) || (total == VS_INDETERMINATE)) {
        break;
      }
      if (req->qtype == DNSSEC_TYPE_CNAME) {
        /* the answer is the synthesized CNAME, which must match */
        unsigned char target[DNSSEC_NAME_MAX];
        first = rrset_find(m, DNSSEC_SECT_ANSWER, sname, DNSSEC_TYPE_CNAME);
        if ((first == DNSSEC_NONE) ||
            !cname_target(m, &m->rrs[first], target) ||
            !ares_dnssec_name_eq(target, next) || !rrset_single(m, first)) {
          why(v, "CNAME for %s does not match the DNAME",
              NAMESTR(sname, v->nb[0]));
          total = VS_BOGUS;
          break;
        }
        req->amsg   = m;
        req->afirst = first;
        req->rcode  = DNSSEC_RCODE_NOERROR;
        break;
      }
      memcpy(sname, next, DNSSEC_NAME_MAX);
    } else {
      first = rrset_find(m, DNSSEC_SECT_ANSWER, sname, req->qtype);
      if (first != DNSSEC_NONE) {
        r = answer_rrset(v, m, first, NULL, &ttl);
        if (r == VS_PENDING) {
          return r;
        }
        total       = vs_combine(total, r);
        req->amsg   = m;
        req->afirst = first;
        req->rcode  = DNSSEC_RCODE_NOERROR;
        break;
      }
      if (req->qtype == DNSSEC_TYPE_CNAME) {
        goto negative;
      }
      first = rrset_find(m, DNSSEC_SECT_ANSWER, sname, DNSSEC_TYPE_CNAME);
      if (first == DNSSEC_NONE) {
        goto negative;
      }
      if (!cname_target(m, &m->rrs[first], next)) {
        why(v, "bad CNAME record for %s", NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      r = answer_rrset(v, m, first, NULL, &ttl);
      if (r == VS_PENDING) {
        return r;
      }
      total = vs_combine(total, r);
      if ((total == VS_BOGUS) || (total == VS_INDETERMINATE)) {
        break;
      }
      memcpy(sname, next, DNSSEC_NAME_MAX);
    }

    if (++hops > DNSSEC_MAX_CHAIN) {
      why(v, "too many CNAME and DNAME records");
      return VS_INDETERMINATE;
    }
    memcpy(req->chain[hops - 1], sname, DNSSEC_NAME_MAX);
    req->nchain = hops;
    continue;

negative:
    /* A response for a CNAME chain can end before the last name (like
       when it is in another zone), then ask for the rest. */
    if (hops && !ares_dnssec_name_eq(m->qname, sname) &&
        !authority_has_denial(m)) {
      r = query_get(v, sname, req->qtype, &m);
      if (r == VS_PENDING) {
        return r;
      }
      if (r == VS_SECURE) {
        continue;
      }
      total = vs_combine(total, r);
      break;
    }
    r = answer_negative(v, m, sname, req->qtype, &ttl);
    if (r == VS_PENDING) {
      return r;
    }
    total = vs_combine(total, r);
    break;
  }

  req->ttl = (ttl == 0xffffffff) ? 0 : ttl;
  return total;
}

/*
 * API
 */

static ares_status_t anchor_add(ares_dnssec_ctx_t   *ctx,
                                const unsigned char *name, unsigned short type,
                                const unsigned char *rdata, size_t rdlen)
{
  struct dnssec_anchor *a = ares_malloc_zero(sizeof(*a) + rdlen);
  if (!a) {
    return ARES_ENOMEM;
  }
  ares_dnssec_name_lower(a->name, name);
  a->type  = type;
  a->rdata = (unsigned char *)a + sizeof(*a);
  memcpy(a->rdata, rdata, rdlen);
  a->rdlen     = (unsigned short)rdlen;
  a->next      = ctx->anchors;
  ctx->anchors = a;
  return ARES_SUCCESS;
}

/* Parse a decimal number from the token */
static ares_bool_t token_num(const char *tok, size_t len, unsigned long max,
                             unsigned long *pnum)
{
  unsigned long num = 0;
  size_t        i;
  if (!len) {
    return ARES_FALSE;
  }
  for (i = 0; i < len; i++) {
    unsigned long digit;
    if (!ares_isdigit(tok[i])) {
      return ARES_FALSE;
    }
    digit = (unsigned long)(tok[i] - '0');
    if (num > (max - digit) / 10) {
      return ARES_FALSE;
    }
    num = num * 10 + digit;
  }
  *pnum = num;
  return ARES_TRUE;
}

static int b64val(char c)
{
  if ((c >= 'A') && (c <= 'Z')) {
    return c - 'A';
  }
  if ((c >= 'a') && (c <= 'z')) {
    return c - 'a' + 26;
  }
  if ((c >= '0') && (c <= '9')) {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

/* Decode base64 (RFC 4648 section 4) split over 'ntok' tokens into 'out'.
   Padding is required and only allowed at the end. */
static ares_bool_t b64_decode(const char * const *tok, const size_t *toklen,
                              size_t ntok, unsigned char *out, size_t outmax,
                              size_t *poutlen)
{
  unsigned int acc    = 0;
  size_t       nchars = 0;
  size_t       npad   = 0;
  size_t       outlen = 0;
  size_t       t;

  for (t = 0; t < ntok; t++) {
    size_t i;
    for (i = 0; i < toklen[t]; i++) {
      char c = tok[t][i];
      int  val;
      if (c == '=') {
        npad++;
        val = 0;
      } else {
        val = b64val(c);
        if ((val < 0) || npad) {
          return ARES_FALSE;
        }
      }
      acc = (acc << 6) | (unsigned int)val;
      if ((++nchars % 4) == 0) {
        size_t n = 3;
        if (npad > 2) {
          return ARES_FALSE;
        }
        n -= npad;
        if (outlen + n > outmax) {
          return ARES_FALSE;
        }
        out[outlen++] = (unsigned char)(acc >> 16);
        if (n > 1) {
          out[outlen++] = (unsigned char)(acc >> 8);
        }
        if (n > 2) {
          out[outlen++] = (unsigned char)acc;
        }
        acc = 0;
      } else if (npad && ((nchars % 4) < 3)) {
        return ARES_FALSE; /* padding in the first two positions */
      }
    }
  }
  if (nchars % 4) {
    return ARES_FALSE;
  }
  *poutlen = outlen;
  return ARES_TRUE;
}

static int hexval(char c)
{
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  }
  if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  }
  if ((c >= 'A') && (c <= 'F')) {
    return c - 'A' + 10;
  }
  return -1;
}

#define ANCHOR_MAX_TOKENS 64

ares_status_t ares_dnssec_ctx_add_anchor(ares_dnssec_ctx_t *ctx, const char *rr)
{
  const char    *tok[ANCHOR_MAX_TOKENS];
  size_t         toklen[ANCHOR_MAX_TOKENS];
  size_t         ntok = 0;
  size_t         t;
  unsigned char  name[DNSSEC_NAME_MAX];
  unsigned char  rdata[1024];
  size_t         rdlen = 0;
  unsigned long  num;
  unsigned short type;

  /* split into tokens, skipping parentheses and comments */
  while (*rr && (*rr != ';')) {
    const char *start;
    if (ares_isspace(*rr) || (*rr == '(') || (*rr == ')')) {
      rr++;
      continue;
    }
    start = rr;
    while (*rr && !ares_isspace(*rr) && (*rr != '(') && (*rr != ')') &&
           (*rr != ';')) {
      rr++;
    }
    if (ntok >= ANCHOR_MAX_TOKENS) {
      return ARES_EFORMERR;
    }
    tok[ntok]    = start;
    toklen[ntok] = (size_t)(rr - start);
    ntok++;
  }
  if (ntok < 2) {
    return ARES_EFORMERR;
  }
  if (ares_dnssec_name_parse(tok[0], toklen[0], name)) {
    return ARES_EFORMERR;
  }
  t = 1;
  /* optional TTL and class */
  if ((t < ntok) && token_num(tok[t], toklen[t], 0xffffffffUL, &num)) {
    t++;
  }
  if ((t < ntok) && (toklen[t] == 2) && ares_strcaseeq_max(tok[t], "IN", 2)) {
    t++;
  }
  if (t >= ntok) {
    return ARES_EFORMERR;
  }
  if ((toklen[t] == 2) && ares_strcaseeq_max(tok[t], "DS", 2)) {
    type = DNSSEC_TYPE_DS;
  } else if ((toklen[t] == 6) && ares_strcaseeq_max(tok[t], "DNSKEY", 6)) {
    type = DNSSEC_TYPE_DNSKEY;
  } else {
    return ARES_EFORMERR;
  }
  t++;
  if (ntok - t < 4) {
    return ARES_EFORMERR;
  }

  if (type == DNSSEC_TYPE_DS) {
    /* key tag, algorithm, digest type, digest in hex */
    if (!token_num(tok[t], toklen[t], 0xffff, &num)) {
      return ARES_EFORMERR;
    }
    rdata[0] = (unsigned char)(num >> 8);
    rdata[1] = (unsigned char)num;
    if (!token_num(tok[t + 1], toklen[t + 1], 0xff, &num)) {
      return ARES_EFORMERR;
    }
    rdata[2] = (unsigned char)num;
    if (!token_num(tok[t + 2], toklen[t + 2], 0xff, &num)) {
      return ARES_EFORMERR;
    }
    rdata[3] = (unsigned char)num;
    rdlen    = 4;
    for (t += 3; t < ntok; t++) {
      size_t i;
      if (toklen[t] & 1) {
        return ARES_EFORMERR;
      }
      for (i = 0; i < toklen[t]; i += 2) {
        int hi = hexval(tok[t][i]);
        int lo = hexval(tok[t][i + 1]);
        if ((hi < 0) || (lo < 0) || (rdlen >= sizeof(rdata))) {
          return ARES_EFORMERR;
        }
        rdata[rdlen++] = (unsigned char)((hi << 4) | lo);
      }
    }
    if (rdlen < 5) {
      return ARES_EFORMERR;
    }
    return anchor_add(ctx, name, type, rdata, rdlen);
  }

  /* DNSKEY: flags, protocol, algorithm, public key in base64 */
  if (!token_num(tok[t], toklen[t], 0xffff, &num)) {
    return ARES_EFORMERR;
  }
  rdata[0] = (unsigned char)(num >> 8);
  rdata[1] = (unsigned char)num;
  if (!token_num(tok[t + 1], toklen[t + 1], 0xff, &num) || (num != 3)) {
    return ARES_EFORMERR;
  }
  rdata[2] = (unsigned char)num;
  if (!token_num(tok[t + 2], toklen[t + 2], 0xff, &num)) {
    return ARES_EFORMERR;
  }
  rdata[3] = (unsigned char)num;
  if (!b64_decode(&tok[t + 3], &toklen[t + 3], ntok - t - 3, &rdata[4],
                  sizeof(rdata) - 4, &rdlen) ||
      !rdlen) {
    return ARES_EFORMERR;
  }
  return anchor_add(ctx, name, type, rdata, rdlen + 4);
}

void ares_dnssec_ctx_clear_anchors(ares_dnssec_ctx_t *ctx)
{
  while (ctx->anchors) {
    struct dnssec_anchor *a = ctx->anchors;
    ctx->anchors            = a->next;
    ares_free(a);
  }
}

/* The root zone trust anchors, https://data.iana.org/root-anchors/ */
static const char * const root_anchors[] = {
  /* KSK-2017 */
  ". IN DS 20326 8 2 "
  "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
  /* KSK-2024 */
  ". IN DS 38696 8 2 "
  "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
};

ares_status_t ares_dnssec_ctx_create(const ares_dnssec_crypto_t *crypto,
                                     ares_dnssec_ctx_t         **pctx)
{
  ares_dnssec_ctx_t *ctx;
  size_t             i;
  *pctx = NULL;
  if (!ares_dnssec_crypto_valid(crypto)) {
    return ARES_EFORMERR;
  }
  ctx = ares_malloc_zero(sizeof(*ctx));
  if (!ctx) {
    return ARES_ENOMEM;
  }
  ctx->crypto = *crypto;
  for (i = 0; i < (sizeof(root_anchors) / sizeof(root_anchors[0])); i++) {
    ares_status_t result = ares_dnssec_ctx_add_anchor(ctx, root_anchors[i]);
    if (result) {
      ares_dnssec_ctx_destroy(ctx);
      return result;
    }
  }
  *pctx = ctx;
  return ARES_SUCCESS;
}

void ares_dnssec_ctx_destroy(ares_dnssec_ctx_t *ctx)
{
  if (!ctx) {
    return;
  }
  ares_dnssec_ctx_clear_anchors(ctx);
  while (ctx->queries) {
    struct dnssec_query *q = ctx->queries;
    ctx->queries           = q->next;
    ares_dnssec_msg_free(q->msg);
    ares_free(q);
  }
  while (ctx->zones) {
    struct dnssec_zone *z = ctx->zones;
    ctx->zones            = z->next;
    ares_free(z);
  }
  ares_free(ctx);
}

void ares_dnssec_ctx_set_flags(ares_dnssec_ctx_t *ctx, unsigned int flags)
{
  ctx->flags = flags;
}

void ares_dnssec_ctx_set_time(ares_dnssec_ctx_t *ctx, time_t now)
{
  ctx->fixed_now = now;
}

ares_bool_t ares_dnssec_ctx_next_query(ares_dnssec_ctx_t *ctx, char *name,
                                       size_t namelen, unsigned short *qtype)
{
  struct dnssec_query *q;
  struct dnssec_query *oldest = NULL;
  /* the list has the newest first, send the oldest first */
  for (q = ctx->queries; q; q = q->next) {
    if (q->state == Q_WANTED) {
      oldest = q;
    }
  }
  if (!oldest) {
    return ARES_FALSE;
  }
  oldest->state = Q_SENT;
  ares_dnssec_name_str(oldest->name, name, namelen);
  *qtype = oldest->qtype;
  return ARES_TRUE;
}

static struct dnssec_query *query_by_str(ares_dnssec_ctx_t *ctx,
                                         const char *name, unsigned short qtype)
{
  unsigned char wire[DNSSEC_NAME_MAX];
  if (ares_dnssec_name_parse(name, strlen(name), wire)) {
    return NULL;
  }
  return query_find(ctx, wire, qtype);
}

ares_status_t ares_dnssec_ctx_add_response(ares_dnssec_ctx_t   *ctx,
                                           const char          *name,
                                           unsigned short       qtype,
                                           const unsigned char *msg,
                                           size_t               msglen)
{
  struct dnssec_query *q = query_by_str(ctx, name, qtype);
  struct dnssec_msg   *m = NULL;
  ares_status_t        result;

  if (!q) {
    return ARES_EFORMERR;
  }
  if (q->state == Q_DONE) {
    return ARES_SUCCESS;
  }
  /* without a usable response, the query failed */
  q->state = Q_DONE;
  result   = ares_dnssec_msg_parse(msg, msglen, &m);
  if (result == ARES_ENOMEM) {
    return result;
  }
  if (m && ((m->qtype != qtype) || (m->qclass != DNSSEC_CLASS_IN) ||
            !ares_dnssec_name_eq(m->qname, q->name) ||
            (ctx->nbytes + m->size > DNSSEC_MAX_BYTES))) {
    /* not the response to this query, or too much data */
    ares_dnssec_msg_free(m);
    m = NULL;
  }
  if (m) {
    ctx->nbytes += m->size;
  }
  q->msg = m;
  return ARES_SUCCESS;
}

ares_status_t ares_dnssec_ctx_add_failure(ares_dnssec_ctx_t *ctx,
                                          const char        *name,
                                          unsigned short     qtype)
{
  struct dnssec_query *q = query_by_str(ctx, name, qtype);
  if (!q) {
    return ARES_EFORMERR;
  }
  q->state = Q_DONE;
  return ARES_SUCCESS;
}

size_t ares_dnssec_ctx_pending(const ares_dnssec_ctx_t *ctx)
{
  const struct dnssec_query *q;
  size_t                     n = 0;
  for (q = ctx->queries; q; q = q->next) {
    if (q->state != Q_DONE) {
      n++;
    }
  }
  return n;
}

ares_status_t ares_dnssec_req_create(ares_dnssec_ctx_t *ctx, const char *name,
                                     unsigned short      qtype,
                                     ares_dnssec_req_t **preq)
{
  ares_dnssec_req_t *req;
  unsigned char      wire[DNSSEC_NAME_MAX];

  *preq = NULL;
  /* meta types and types that are not validated as answers */
  if (!qtype || (qtype == DNSSEC_TYPE_OPT) || (qtype == DNSSEC_TYPE_RRSIG) ||
      (qtype == DNSSEC_TYPE_NXNAME) || ((qtype >= 249) && (qtype <= 255))) {
    return ARES_EFORMERR;
  }
  if (ares_dnssec_name_parse(name, strlen(name), wire)) {
    return ARES_EFORMERR;
  }
  req = ares_malloc_zero(sizeof(*req));
  if (!req) {
    return ARES_ENOMEM;
  }
  req->ctx   = ctx;
  req->rdata = ares_buf_create();
  if (!req->rdata) {
    ares_free(req);
    return ARES_ENOMEM;
  }
  ares_dnssec_name_lower(req->qname, wire);
  req->qtype  = qtype;
  req->status = ARES_DNSSEC_INDETERMINATE;
  *preq       = req;
  return ARES_SUCCESS;
}

void ares_dnssec_req_destroy(ares_dnssec_req_t *req)
{
  if (req) {
    ares_buf_destroy(req->rdata);
    ares_free(req->rdoffs);
    ares_free(req);
  }
}

ares_status_t ares_dnssec_req_run(ares_dnssec_req_t *req, ares_bool_t *done)
{
  ares_dnssec_ctx_t *ctx = req->ctx;
  struct vctx        v;
  time_t             now;
  vstat              r;

  *done = req->done;
  if (req->done) {
    return ARES_SUCCESS;
  }
  memset(&v, 0, sizeof(v));
  v.ctx = ctx;
  v.req = req;
  now   = ctx->fixed_now ? ctx->fixed_now : time(NULL);
  v.now = (unsigned int)now; /* seconds modulo 2^32, RFC 4034 3.1.5 */

  r = req_eval(&v);
  if (v.error) {
    return v.error;
  }
  if (r == VS_PENDING) {
    if (ares_dnssec_ctx_pending(ctx)) {
      return ARES_SUCCESS;
    }
    /* cannot happen, but never wait for nothing */
    why(&v, "validation stalled");
    r = VS_INDETERMINATE;
  }

  switch (r) {
    case VS_SECURE:
      req->status = ARES_DNSSEC_SECURE;
      break;
    case VS_INSECURE:
      req->status = ARES_DNSSEC_INSECURE;
      break;
    case VS_BOGUS:
      req->status = ARES_DNSSEC_BOGUS;
      break;
    default:
      req->status = ARES_DNSSEC_INDETERMINATE;
      break;
  }
  if (req->status != ARES_DNSSEC_SECURE) {
    ares_strcpy(req->reason, v.reason, sizeof(req->reason));
  }

  /* only hand out records that are secure or proven insecure */
  req->acount = 0;
  req->done   = ARES_TRUE;
  *done       = ARES_TRUE;
  if (req->amsg && ((req->status == ARES_DNSSEC_SECURE) ||
                    (req->status == ARES_DNSSEC_INSECURE))) {
    const struct dnssec_msg *m = req->amsg;
    size_t                   n = 0;
    size_t                   i;
    for (i = req->afirst; i < m->nrrs; i++) {
      if (rr_same_set(m, &m->rrs[i], &m->rrs[req->afirst])) {
        n++;
      }
    }
    req->rdoffs = ares_malloc_zero_array(n + 1, sizeof(size_t));
    if (!req->rdoffs) {
      req->status = ARES_DNSSEC_INDETERMINATE;
      return ARES_ENOMEM;
    }
    for (i = req->afirst; i < m->nrrs; i++) {
      if (!rr_same_set(m, &m->rrs[i], &m->rrs[req->afirst])) {
        continue;
      }
      req->rdoffs[req->acount++] = ares_buf_len(req->rdata);
      if (ares_dnssec_rdata_canonical(m, &m->rrs[i], req->rdata)) {
        /* validated records are well-formed, unless out of memory */
        req->acount = 0;
        req->status = ARES_DNSSEC_INDETERMINATE;
        return ARES_ENOMEM;
      }
    }
    req->rdoffs[req->acount] = ares_buf_len(req->rdata);
  }
  return ARES_SUCCESS;
}

ares_dnssec_status_t ares_dnssec_req_status(const ares_dnssec_req_t *req)
{
  return req->done ? req->status : ARES_DNSSEC_INDETERMINATE;
}

const char *ares_dnssec_req_reason(const ares_dnssec_req_t *req)
{
  return (req->done && req->reason[0]) ? req->reason : NULL;
}

int ares_dnssec_req_rcode(const ares_dnssec_req_t *req)
{
  return req->rcode;
}

unsigned int ares_dnssec_req_ttl(const ares_dnssec_req_t *req)
{
  return req->ttl;
}

size_t ares_dnssec_req_count(const ares_dnssec_req_t *req)
{
  return req->acount;
}

ares_bool_t ares_dnssec_req_rdata(const ares_dnssec_req_t *req, size_t idx,
                                  const unsigned char **prdata, size_t *prdlen)
{
  static const unsigned char empty[1] = { 0 };
  const unsigned char       *p;
  size_t                     len;
  if (idx >= req->acount) {
    return ARES_FALSE;
  }
  p       = ares_buf_peek(req->rdata, &len);
  *prdata = p ? p + req->rdoffs[idx] : empty;
  *prdlen = req->rdoffs[idx + 1] - req->rdoffs[idx];
  return ARES_TRUE;
}

/* Append a resource record in wire format */
static ares_status_t rr_write(ares_buf_t *buf, const unsigned char *owner,
                              unsigned short type, unsigned short rclass,
                              unsigned int ttl, const unsigned char *rdata,
                              size_t rdlen)
{
  if (ares_buf_append(buf, owner, ares_dnssec_name_len(owner)) ||
      ares_buf_append_be16(buf, type) || ares_buf_append_be16(buf, rclass) ||
      ares_buf_append_be32(buf, ttl) ||
      ares_buf_append_be16(buf, (unsigned short)rdlen) ||
      (rdlen && ares_buf_append(buf, rdata, rdlen))) {
    return ARES_ENOMEM;
  }
  return ARES_SUCCESS;
}

ares_status_t ares_dnssec_req_response(const ares_dnssec_req_t *req,
                                       ares_buf_t              *buf)
{
  static const unsigned char root[1] = { 0 };
  ares_bool_t                ok      = (req->status == ARES_DNSSEC_SECURE) ||
                   (req->status == ARES_DNSSEC_INSECURE);
  /* QR, RD and RA, plus AD (RFC 4035 section 3.2.3) when secure */
  unsigned short flags   = 0x8180;
  size_t         ancount = 0;
  size_t         i;

  if (!req->done) {
    return ARES_EFORMERR;
  }
  if (ok) {
    ancount = req->nchain + req->acount;
    if (req->status == ARES_DNSSEC_SECURE) {
      flags |= 0x0020;
    }
    flags |= (unsigned short)(req->rcode & 0x0f);
  } else {
    flags |= 2; /* SERVFAIL */
  }

  if (ares_buf_append_be16(buf, 0) || ares_buf_append_be16(buf, flags) ||
      ares_buf_append_be16(buf, 1) ||
      ares_buf_append_be16(buf, (unsigned short)ancount) ||
      ares_buf_append_be16(buf, 0) || ares_buf_append_be16(buf, ok ? 0 : 1) ||
      ares_buf_append(buf, req->qname, ares_dnssec_name_len(req->qname)) ||
      ares_buf_append_be16(buf, req->qtype) ||
      ares_buf_append_be16(buf, DNSSEC_CLASS_IN)) {
    return ARES_ENOMEM;
  }

  if (ok) {
    const unsigned char *owner = req->qname;
    /* the CNAME and DNAME links as CNAME records */
    for (i = 0; i < req->nchain; i++) {
      if (rr_write(buf, owner, DNSSEC_TYPE_CNAME, DNSSEC_CLASS_IN, req->ttl,
                   req->chain[i], ares_dnssec_name_len(req->chain[i]))) {
        return ARES_ENOMEM;
      }
      owner = req->chain[i];
    }
    if (req->acount) {
      const struct dnssec_msg *m     = req->amsg;
      const struct dnssec_rr  *first = &m->rrs[req->afirst];
      for (i = 0; i < req->acount; i++) {
        const unsigned char *rdata;
        size_t               rdlen;
        if (!ares_dnssec_req_rdata(req, i, &rdata, &rdlen) ||
            (rdlen > 0xffff)) {
          return ARES_EFORMERR;
        }
        if (rr_write(buf, DNSSEC_RR_OWNER(m, first), first->type, first->rclass,
                     req->ttl, rdata, rdlen)) {
          return ARES_ENOMEM;
        }
      }
    }
  } else {
    /* OPT record (RFC 6891) with an Extended DNS Error (RFC 8914): 6
       "DNSSEC Bogus" or 0 "Other Error", with the reason as text */
    size_t textlen = ares_strlen(req->reason);
    if (textlen > 400) {
      textlen = 400;
    }
    if (ares_buf_append(buf, root, 1) ||
        ares_buf_append_be16(buf, DNSSEC_TYPE_OPT) ||
        ares_buf_append_be16(buf, 1232) || ares_buf_append_be32(buf, 0) ||
        ares_buf_append_be16(buf, (unsigned short)(6 + textlen)) ||
        ares_buf_append_be16(buf, 15) ||
        ares_buf_append_be16(buf, (unsigned short)(2 + textlen)) ||
        ares_buf_append_be16(buf, (req->status == ARES_DNSSEC_BOGUS) ? 6 : 0) ||
        (textlen &&
         ares_buf_append(buf, (const unsigned char *)req->reason, textlen))) {
      return ARES_ENOMEM;
    }
  }
  return ARES_SUCCESS;
}

const char *ares_dnssec_status_str(ares_dnssec_status_t status)
{
  switch (status) {
    case ARES_DNSSEC_SECURE:
      return "secure";
    case ARES_DNSSEC_INSECURE:
      return "insecure";
    case ARES_DNSSEC_BOGUS:
      return "bogus";
    default:
      return "indeterminate";
  }
}
