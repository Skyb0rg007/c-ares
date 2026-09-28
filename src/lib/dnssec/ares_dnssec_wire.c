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

/* DNS wire format handling for the DNSSEC validator: names, messages and
   the canonical form of records (RFC 1035, RFC 3597, RFC 4034) */

#define DNSSEC_MSG_MAX 65535
/* Most records in the answer and authority sections of a message. Real
   responses have far fewer, this bounds the work a large one causes. */
#define DNSSEC_MSG_MAX_RRS 512
/* Most compression pointers followed in one name */
#define DNSSEC_MAX_POINTERS 128

static unsigned short wire16(const unsigned char *p)
{
  return (unsigned short)((p[0] << 8) | p[1]);
}

static unsigned int wire32(const unsigned char *p)
{
  return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
         ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

static unsigned char lowc(unsigned char c)
{
  return ((c >= 'A') && (c <= 'Z')) ? (unsigned char)(c + ('a' - 'A')) : c;
}

ares_status_t ares_dnssec_read_name(const unsigned char *buf, size_t len,
                                    size_t *offset, ares_bool_t compress,
                                    unsigned char out[DNSSEC_NAME_MAX])
{
  size_t       pos      = *offset;
  size_t       limit    = pos; /* compression pointers must point before this */
  size_t       end      = 0;
  size_t       olen     = 0;
  unsigned int pointers = 0;
  ares_bool_t  jumped   = ARES_FALSE;

  for (;;) {
    unsigned char c;
    if (pos >= len) {
      return ARES_EBADRESP;
    }
    c = buf[pos];
    if ((c & 0xc0) == 0xc0) {
      size_t ptr;
      if (!compress || (pos + 1 >= len) || (++pointers > DNSSEC_MAX_POINTERS)) {
        return ARES_EBADRESP;
      }
      ptr = ((size_t)(c & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) {
        end    = pos + 2;
        jumped = ARES_TRUE;
      }
      /* Only allow pointers going strictly backwards from the previous
         jump target. That guarantees termination. */
      if (ptr >= limit) {
        return ARES_EBADRESP;
      }
      limit = ptr;
      pos   = ptr;
      continue;
    }
    if (c & 0xc0) { /* extended label types are not supported */
      return ARES_EBADRESP;
    }
    if ((pos + 1 + c > len) || (olen + 1 + c > DNSSEC_NAME_MAX)) {
      return ARES_EBADRESP;
    }
    memcpy(&out[olen], &buf[pos], 1 + (size_t)c);
    olen += 1 + (size_t)c;
    pos  += 1 + (size_t)c;
    if (!c) {
      break;
    }
  }
  *offset = jumped ? end : pos;
  return ARES_SUCCESS;
}

size_t ares_dnssec_name_len(const unsigned char *name)
{
  size_t len = 0;
  while (name[len]) {
    len += 1 + (size_t)name[len];
  }
  return len + 1;
}

unsigned int ares_dnssec_name_labels(const unsigned char *name)
{
  unsigned int labels = 0;
  while (*name) {
    labels++;
    name += 1 + *name;
  }
  return labels;
}

unsigned int ares_dnssec_name_sig_labels(const unsigned char *name)
{
  unsigned int labels = ares_dnssec_name_labels(name);
  if ((name[0] == 1) && (name[1] == '*')) {
    labels--;
  }
  return labels;
}

ares_bool_t ares_dnssec_name_eq(const unsigned char *a, const unsigned char *b)
{
  for (;;) {
    unsigned char len = *a;
    unsigned char i;
    if (len != *b) {
      return ARES_FALSE;
    }
    if (!len) {
      return ARES_TRUE;
    }
    for (i = 1; i <= len; i++) {
      if (lowc(a[i]) != lowc(b[i])) {
        return ARES_FALSE;
      }
    }
    a += 1 + len;
    b += 1 + len;
  }
}

const unsigned char *ares_dnssec_name_suffix(const unsigned char *name,
                                             unsigned int         labels)
{
  unsigned int have = ares_dnssec_name_labels(name);
  while (have > labels) {
    name += 1 + *name;
    have--;
  }
  return name;
}

ares_bool_t ares_dnssec_name_sub(const unsigned char *name,
                                 const unsigned char *parent)
{
  unsigned int ln = ares_dnssec_name_labels(name);
  unsigned int lp = ares_dnssec_name_labels(parent);
  if (ln < lp) {
    return ARES_FALSE;
  }
  return ares_dnssec_name_eq(ares_dnssec_name_suffix(name, lp), parent);
}

/* store the offsets of the labels of 'name', return the number of them */
static unsigned int name_offsets(const unsigned char *name,
                                 unsigned char offs[DNSSEC_LABELS_MAX + 1])
{
  unsigned int n   = 0;
  size_t       pos = 0;
  while (name[pos] && (n <= DNSSEC_LABELS_MAX)) {
    offs[n++]  = (unsigned char)pos;
    pos       += 1 + (size_t)name[pos];
  }
  return n;
}

static int label_cmp(const unsigned char *a, const unsigned char *b)
{
  unsigned char la = a[0];
  unsigned char lb = b[0];
  unsigned char i;
  for (i = 1; (i <= la) && (i <= lb); i++) {
    unsigned char ca = lowc(a[i]);
    unsigned char cb = lowc(b[i]);
    if (ca != cb) {
      return (int)ca - (int)cb;
    }
  }
  return (int)la - (int)lb;
}

unsigned int ares_dnssec_name_common(const unsigned char *a,
                                     const unsigned char *b)
{
  unsigned char oa[DNSSEC_LABELS_MAX + 1];
  unsigned char ob[DNSSEC_LABELS_MAX + 1];
  unsigned int  na     = name_offsets(a, oa);
  unsigned int  nb     = name_offsets(b, ob);
  unsigned int  common = 0;
  while ((common < na) && (common < nb) &&
         !label_cmp(&a[oa[na - common - 1]], &b[ob[nb - common - 1]])) {
    common++;
  }
  return common;
}

int ares_dnssec_name_cmp(const unsigned char *a, const unsigned char *b)
{
  unsigned char oa[DNSSEC_LABELS_MAX + 1];
  unsigned char ob[DNSSEC_LABELS_MAX + 1];
  unsigned int  na = name_offsets(a, oa);
  unsigned int  nb = name_offsets(b, ob);
  unsigned int  i;
  for (i = 1; (i <= na) && (i <= nb); i++) {
    int rc = label_cmp(&a[oa[na - i]], &b[ob[nb - i]]);
    if (rc) {
      return rc;
    }
  }
  return (int)na - (int)nb;
}

void ares_dnssec_name_lower(unsigned char *dest, const unsigned char *name)
{
  size_t len = ares_dnssec_name_len(name);
  size_t i;
  for (i = 0; i < len; i++) {
    dest[i] = lowc(name[i]);
  }
  /* the length octets are all < 64 and not affected by lowc() */
}

void ares_dnssec_name_str(const unsigned char *name, char *out, size_t outlen)
{
  size_t o = 0;
  if (!outlen) {
    return;
  }
  if (!*name) {
    if (outlen > 1) {
      out[o++] = '.';
    }
    out[o] = 0;
    return;
  }
  while (*name) {
    unsigned char len = *name++;
    unsigned char i;
    for (i = 0; i < len; i++) {
      unsigned char c = name[i];
      if ((c <= 0x20) || (c >= 0x7f) || (c == '.') || (c == '\\') ||
          (c == '"') || (c == '(') || (c == ')') || (c == ';') || (c == '@') ||
          (c == '$')) {
        if (o + 4 >= outlen) {
          goto out;
        }
        out[o++] = '\\';
        out[o++] = (char)('0' + c / 100);
        out[o++] = (char)('0' + (c / 10) % 10);
        out[o++] = (char)('0' + c % 10);
      } else {
        if (o + 1 >= outlen) {
          goto out;
        }
        out[o++] = (char)c;
      }
    }
    if (o + 1 >= outlen) {
      goto out;
    }
    out[o++]  = '.';
    name     += len;
  }
out:
  out[o] = 0;
}

ares_status_t ares_dnssec_name_parse(const char *str, size_t len,
                                     unsigned char out[DNSSEC_NAME_MAX])
{
  size_t        o    = 0; /* where the current label's length octet is */
  size_t        i    = 0;
  unsigned char llen = 0;

  if ((len == 1) && (str[0] == '.')) {
    out[0] = 0;
    return ARES_SUCCESS;
  }
  if (!len) {
    return ARES_EFORMERR;
  }

  while (i < len) {
    unsigned int c = (unsigned char)str[i++];
    if (c == '.') {
      if (!llen) { /* empty label */
        return ARES_EFORMERR;
      }
      out[o]  = llen;
      o      += 1 + (size_t)llen;
      llen    = 0;
      continue;
    }
    if (c == '\\') {
      if (i >= len) {
        return ARES_EFORMERR;
      }
      if (ares_isdigit(str[i])) {
        if ((i + 3 > len) || !ares_isdigit(str[i + 1]) ||
            !ares_isdigit(str[i + 2])) {
          return ARES_EFORMERR;
        }
        c = (unsigned int)((str[i] - '0') * 100 + (str[i + 1] - '0') * 10 +
                           (str[i + 2] - '0'));
        if (c > 255) {
          return ARES_EFORMERR;
        }
        i += 3;
      } else {
        c = (unsigned char)str[i++];
      }
    }
    /* room for this octet, the label length and the root label */
    if ((llen >= 63) || (o + 1 + llen + 1 >= DNSSEC_NAME_MAX)) {
      return ARES_EFORMERR;
    }
    out[o + 1 + llen] = (unsigned char)c;
    llen++;
  }
  if (llen) {
    out[o]  = llen;
    o      += 1 + (size_t)llen;
  }
  out[o] = 0;
  return ARES_SUCCESS;
}

void ares_dnssec_msg_free(struct dnssec_msg *msg)
{
  if (msg) {
    ares_free(msg->buf);
    ares_free(msg->names);
    ares_free(msg->rrs);
    ares_free(msg);
  }
}

ares_status_t ares_dnssec_msg_parse(const unsigned char *buf, size_t len,
                                    struct dnssec_msg **pmsg)
{
  struct dnssec_msg *m     = NULL;
  ares_buf_t        *names = NULL;
  unsigned char      name[DNSSEC_NAME_MAX];
  size_t             pos = 12;
  size_t             nrrs;
  size_t             an;
  size_t             namelen;
  size_t             i;
  ares_status_t      result = ARES_EBADRESP;

  *pmsg = NULL;
  if ((len < 12) || (len > DNSSEC_MSG_MAX)) {
    goto out;
  }
  /* must be a response (QR), a standard query and not truncated (TC) */
  if (!(buf[2] & 0x80) || (buf[2] & 0x78) || (buf[2] & 0x02)) {
    goto out;
  }
  if (wire16(&buf[4]) != 1) {
    goto out;
  }
  an   = wire16(&buf[6]);
  nrrs = an + wire16(&buf[8]);

  m = ares_malloc_zero(sizeof(*m));
  if (!m) {
    result = ARES_ENOMEM;
    goto out;
  }
  names = ares_buf_create();
  if (!names) {
    result = ARES_ENOMEM;
    goto out;
  }
  m->flags = wire16(&buf[2]);
  m->rcode = (unsigned char)(buf[3] & 0x0f);

  if (ares_dnssec_read_name(buf, len, &pos, ARES_TRUE, m->qname) ||
      (pos + 4 > len)) {
    goto out;
  }
  m->qtype   = wire16(&buf[pos]);
  m->qclass  = wire16(&buf[pos + 2]);
  pos       += 4;

  /* every record is at least 11 bytes */
  if ((nrrs > (len - pos) / 11) || (nrrs > DNSSEC_MSG_MAX_RRS)) {
    goto out;
  }
  if (nrrs) {
    m->rrs = ares_malloc_zero_array(nrrs, sizeof(struct dnssec_rr));
    if (!m->rrs) {
      result = ARES_ENOMEM;
      goto out;
    }
  }

  for (i = 0; i < nrrs; i++) {
    struct dnssec_rr *rr = &m->rrs[i];
    unsigned int      ttl;
    if (ares_dnssec_read_name(buf, len, &pos, ARES_TRUE, name) ||
        (pos + 10 > len)) {
      goto out;
    }
    rr->owner = ares_buf_len(names);
    if (ares_buf_append(names, name, ares_dnssec_name_len(name))) {
      result = ARES_ENOMEM;
      goto out;
    }
    result     = ARES_EBADRESP;
    rr->type   = wire16(&buf[pos]);
    rr->rclass = wire16(&buf[pos + 2]);
    ttl        = wire32(&buf[pos + 4]);
    /* RFC 2181 section 8: treat TTLs with the top bit set as zero */
    rr->ttl    = (ttl & 0x80000000) ? 0 : ttl;
    rr->rdlen  = wire16(&buf[pos + 8]);
    pos       += 10;
    if (pos + rr->rdlen > len) {
      goto out;
    }
    rr->rdata = pos;
    rr->section =
      (unsigned char)((i < an) ? DNSSEC_SECT_ANSWER : DNSSEC_SECT_AUTHORITY);
    pos += rr->rdlen;
  }
  m->nrrs = nrrs;

  m->buf = ares_malloc(len);
  if (!m->buf) {
    result = ARES_ENOMEM;
    goto out;
  }
  memcpy(m->buf, buf, len);
  m->len   = len;
  m->names = ares_buf_finish_bin(names, &namelen);
  names    = NULL;
  if (!m->names) {
    result = ARES_ENOMEM;
    goto out;
  }
  m->size = sizeof(*m) + len + namelen + nrrs * sizeof(struct dnssec_rr);
  *pmsg   = m;
  m       = NULL;
  result  = ARES_SUCCESS;

out:
  ares_buf_destroy(names);
  ares_dnssec_msg_free(m);
  return result;
}

/*
 * Canonical RDATA.
 *
 * The RDATA layout of the types that contain domain names, as a string of
 * field codes:
 *   'N'  domain name, may be compressed, converted to lowercase
 *   'n'  domain name, not compressed, case kept (NSEC, RFC 6840 5.1)
 *   '2'  two octets, '4' four octets, '6' six octets, 'H' 18 octets
 *   'S'  character-string
 *   '*'  everything up to the end of the RDATA
 * Types not listed here have no names in their RDATA, or names that are
 * neither compressed nor lowercased, and are used as they are.
 */
static const char *rdata_layout(unsigned short type)
{
  switch (type) {
    case DNSSEC_TYPE_NS:
    case DNSSEC_TYPE_MD:
    case DNSSEC_TYPE_MF:
    case DNSSEC_TYPE_CNAME:
    case DNSSEC_TYPE_MB:
    case DNSSEC_TYPE_MG:
    case DNSSEC_TYPE_MR:
    case DNSSEC_TYPE_PTR:
    case DNSSEC_TYPE_DNAME:
      return "N";
    case DNSSEC_TYPE_SOA:
      return "NN*";
    case DNSSEC_TYPE_MINFO:
    case DNSSEC_TYPE_RP:
      return "NN";
    case DNSSEC_TYPE_MX:
    case DNSSEC_TYPE_AFSDB:
    case DNSSEC_TYPE_RT:
    case DNSSEC_TYPE_KX:
      return "2N";
    case DNSSEC_TYPE_PX:
      return "2NN";
    case DNSSEC_TYPE_SRV:
      return "6N";
    case DNSSEC_TYPE_NAPTR:
      return "22SSSN";
    case DNSSEC_TYPE_SIG:
    case DNSSEC_TYPE_RRSIG:
      return "HN*";
    case DNSSEC_TYPE_NXT:
      return "N*";
    case DNSSEC_TYPE_NSEC:
      return "n*";
    default:
      return NULL;
  }
}

/* A6, RFC 2874: prefix length, address suffix, prefix name */
static ares_status_t rdata_a6(const struct dnssec_msg *m, size_t pos,
                              size_t end, ares_buf_t *out)
{
  unsigned char name[DNSSEC_NAME_MAX];
  size_t        suffix;
  unsigned char plen;
  if (pos >= end) {
    return ARES_EBADRESP;
  }
  plen = m->buf[pos];
  if (plen > 128) {
    return ARES_EBADRESP;
  }
  suffix = (size_t)(128 - plen + 7) / 8;
  if (pos + 1 + suffix > end) {
    return ARES_EBADRESP;
  }
  if (ares_buf_append(out, &m->buf[pos], 1 + suffix)) {
    return ARES_ENOMEM;
  }
  pos += 1 + suffix;
  if (!plen) {
    return (pos == end) ? ARES_SUCCESS : ARES_EBADRESP;
  }
  if (ares_dnssec_read_name(m->buf, end, &pos, ARES_FALSE, name) ||
      (pos != end)) {
    return ARES_EBADRESP;
  }
  ares_dnssec_name_lower(name, name);
  return ares_buf_append(out, name, ares_dnssec_name_len(name));
}

ares_status_t ares_dnssec_rdata_canonical(const struct dnssec_msg *m,
                                          const struct dnssec_rr  *rr,
                                          ares_buf_t              *out)
{
  const char *layout = rdata_layout(rr->type);
  size_t      pos    = rr->rdata;
  size_t      end    = rr->rdata + rr->rdlen;

  if (rr->type == DNSSEC_TYPE_A6) {
    return rdata_a6(m, pos, end, out);
  }
  if (!layout) {
    return ares_buf_append(out, &m->buf[pos], rr->rdlen);
  }

  for (; *layout; layout++) {
    unsigned char name[DNSSEC_NAME_MAX];
    size_t        fixed = 0;
    switch (*layout) {
      case 'N':
      case 'n':
        /* Compression pointers can point anywhere before them in the
           message, but the name must start and end inside this RDATA. */
        if (pos >= end) {
          return ARES_EBADRESP;
        }
        if (ares_dnssec_read_name(m->buf, m->len, &pos, (*layout == 'N'),
                                  name) ||
            (pos > end)) {
          return ARES_EBADRESP;
        }
        if (*layout == 'N') {
          ares_dnssec_name_lower(name, name);
        }
        if (ares_buf_append(out, name, ares_dnssec_name_len(name))) {
          return ARES_ENOMEM;
        }
        continue;
      case 'S':
        if (pos >= end) {
          return ARES_EBADRESP;
        }
        fixed = 1 + (size_t)m->buf[pos];
        break;
      case '*':
        fixed = end - pos;
        break;
      case 'H':
        fixed = 18;
        break;
      default:
        fixed = (size_t)(*layout - '0');
        break;
    }
    if (pos + fixed > end) {
      return ARES_EBADRESP;
    }
    if (fixed && ares_buf_append(out, &m->buf[pos], fixed)) {
      return ARES_ENOMEM;
    }
    pos += fixed;
  }
  return (pos == end) ? ARES_SUCCESS : ARES_EBADRESP;
}

ares_bool_t ares_dnssec_bitmap_has(const unsigned char *map, size_t len,
                                   unsigned short type, ares_bool_t *pbad)
{
  size_t      i     = 0;
  int         last  = -1;
  ares_bool_t found = ARES_FALSE;

  *pbad = ARES_FALSE;
  while (i < len) {
    unsigned char window;
    unsigned char blen;
    if (i + 2 > len) {
      *pbad = ARES_TRUE;
      return ARES_FALSE;
    }
    window = map[i];
    blen   = map[i + 1];
    /* windows appear in increasing order, bitmaps are 1-32 octets */
    if (((int)window <= last) || !blen || (blen > 32) || (i + 2 + blen > len)) {
      *pbad = ARES_TRUE;
      return ARES_FALSE;
    }
    last = window;
    if (window == (type >> 8)) {
      size_t octet = (size_t)((type & 0xff) >> 3);
      if (octet < blen) {
        found = !!(map[i + 2 + octet] & (0x80 >> (type & 7)));
      }
    }
    i += 2 + (size_t)blen;
  }
  return found;
}

unsigned short ares_dnssec_keytag(const unsigned char *rdata, size_t rdlen)
{
  unsigned int ac = 0;
  size_t       i;
  if (rdlen < 4) {
    return 0;
  }
  if (rdata[3] == 1) {
    /* RSA/MD5, RFC 4034 appendix B.1 as corrected by RFC 6840 5.5 */
    if (rdlen < 7) {
      return 0;
    }
    return (unsigned short)((rdata[rdlen - 3] << 8) | rdata[rdlen - 2]);
  }
  for (i = 0; i < rdlen; i++) {
    ac += (i & 1) ? rdata[i] : ((unsigned int)rdata[i] << 8);
  }
  ac += (ac >> 16) & 0xffff;
  return (unsigned short)(ac & 0xffff);
}

size_t ares_dnssec_b32hex_decode(const unsigned char *in, size_t inlen,
                                 unsigned char *out, size_t outlen)
{
  unsigned int acc  = 0;
  unsigned int bits = 0;
  size_t       o    = 0;
  size_t       i;
  for (i = 0; i < inlen; i++) {
    unsigned char c = lowc(in[i]);
    unsigned int  v;
    if ((c >= '0') && (c <= '9')) {
      v = (unsigned int)(c - '0');
    } else if ((c >= 'a') && (c <= 'v')) {
      v = (unsigned int)(c - 'a' + 10);
    } else {
      return 0;
    }
    acc   = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (o >= outlen) {
        return 0;
      }
      out[o++]  = (unsigned char)(acc >> bits);
      acc      &= (1U << bits) - 1;
    }
  }
  /* leftover bits must be zero padding */
  if (acc) {
    return 0;
  }
  return o;
}
