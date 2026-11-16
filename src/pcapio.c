#include "pcapio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const cap_t *c, const uint8_t *p) {
    uint16_t v; memcpy(&v, p, 2);
    return c->swap ? (uint16_t)((v >> 8) | (v << 8)) : v;
}
static uint32_t rd32(const cap_t *c, const uint8_t *p) {
    uint32_t v; memcpy(&v, p, 4);
    return c->swap ? __builtin_bswap32(v) : v;
}

int cap_open(cap_t *c, const char *path) {
    memset(c, 0, sizeof *c);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 24) { fprintf(stderr, "%s: too short\n", path); fclose(f); return -1; }
    c->buf = malloc((size_t)n);
    if (!c->buf || fread(c->buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "%s: read failed\n", path); fclose(f); free(c->buf); c->buf = NULL; return -1;
    }
    fclose(f);
    c->len = (size_t)n;

    uint32_t magic; memcpy(&magic, c->buf, 4);
    switch (magic) {
    case 0xa1b2c3d4: c->swap = 0; c->nsec = 0; break;
    case 0xd4c3b2a1: c->swap = 1; c->nsec = 0; break;
    case 0xa1b23c4d: c->swap = 0; c->nsec = 1; break;
    case 0x4d3cb2a1: c->swap = 1; c->nsec = 1; break;
    case 0x0a0d0d0a: { /* pcapng section header block */
        uint32_t bom; memcpy(&bom, c->buf + 8, 4);
        if (bom == 0x1a2b3c4d) c->swap = 0;
        else if (bom == 0x4d3c2b1a) c->swap = 1;
        else { fprintf(stderr, "%s: bad pcapng byte-order magic\n", path); cap_close(c); return -1; }
        c->is_ng = 1;
        c->off = 0;   /* SHB is parsed as an ordinary block by cap_next */
        return 0;
    }
    default:
        fprintf(stderr, "%s: not a pcap/pcapng file\n", path); cap_close(c); return -1;
    }
    c->linktype = (int)(rd32(c, c->buf + 20) & 0x0fffffff);
    c->off = 24;
    return 0;
}

static int next_classic(cap_t *c, cap_pkt_t *p) {
    if (c->off + 16 > c->len) return 0;
    const uint8_t *h = c->buf + c->off;
    uint32_t sec = rd32(c, h), frac = rd32(c, h + 4);
    uint32_t caplen = rd32(c, h + 8), wirelen = rd32(c, h + 12);
    if (caplen > 262144 || c->off + 16 + caplen > c->len) return c->off + 16 + caplen > c->len ? 0 : -1;
    p->data = h + 16;
    p->caplen = caplen;
    p->wirelen = wirelen;
    p->ts_ns = (uint64_t)sec * 1000000000ull + (c->nsec ? frac : (uint64_t)frac * 1000ull);
    p->linktype = c->linktype;
    c->off += 16 + caplen;
    return 1;
}

/* pcapng: walk blocks, return the next packet-bearing one. */
static int next_ng(cap_t *c, cap_pkt_t *p) {
    for (;;) {
        if (c->off + 12 > c->len) return 0;
        const uint8_t *b = c->buf + c->off;
        uint32_t type, blen;
        memcpy(&type, b, 4);                       /* SHB type is endian-neutral */
        if (type == 0x0a0d0d0a) {                  /* new section: may change endianness */
            uint32_t bom; memcpy(&bom, b + 8, 4);
            c->swap = (bom == 0x4d3c2b1a);
            c->n_if = 0;
        }
        type = rd32(c, b);
        blen = rd32(c, b + 4);
        if (blen < 12 || (blen & 3) || c->off + blen > c->len) return c->off + blen > c->len ? 0 : -1;
        c->off += blen;

        if (type == 1) {                           /* Interface Description Block */
            if (c->n_if >= CAP_MAX_IF) { c->n_if++; continue; }   /* counted, packets skipped below */
            int idx = c->n_if++;
            c->if_link[idx] = rd16(c, b + 8);
            c->if_tsdiv[idx] = 1000000;            /* default: microseconds */
            uint32_t o = 16;                       /* options start */
            while (o + 4 <= blen - 4) {
                uint16_t code = rd16(c, b + o), olen = rd16(c, b + o + 2);
                if (code == 0) break;
                if (code == 9 && olen >= 1) {      /* if_tsresol */
                    uint8_t r = b[o + 4];
                    uint64_t d = 1;
                    if (r & 0x80) { for (int i = 0; i < (r & 0x7f) && i < 63; i++) d *= 2; }
                    else          { for (int i = 0; i < r && i < 19; i++) d *= 10; }
                    c->if_tsdiv[idx] = d;
                }
                o += 4 + ((olen + 3u) & ~3u);
            }
            continue;
        }
        if (type == 6 && blen >= 32) {             /* Enhanced Packet Block */
            uint32_t ifid = rd32(c, b + 8);
            uint64_t ts = ((uint64_t)rd32(c, b + 12) << 32) | rd32(c, b + 16);
            uint32_t caplen = rd32(c, b + 20), wirelen = rd32(c, b + 24);
            if (ifid >= (uint32_t)c->n_if || ifid >= CAP_MAX_IF || 28 + caplen > blen) { c->skipped++; continue; }
            uint64_t div = c->if_tsdiv[ifid];
            p->data = b + 28;
            p->caplen = caplen;
            p->wirelen = wirelen;
            p->ts_ns = (ts / div) * 1000000000ull + (ts % div) * 1000000000ull / div;
            p->linktype = c->if_link[ifid];
            return 1;
        }
        if (type == 3 && blen >= 16 && c->n_if > 0) { /* Simple Packet Block */
            uint32_t wirelen = rd32(c, b + 8);
            uint32_t caplen = blen - 16;
            if (caplen > wirelen) caplen = wirelen;
            p->data = b + 12;
            p->caplen = caplen;
            p->wirelen = wirelen;
            p->ts_ns = 0;
            p->linktype = c->if_link[0];
            return 1;
        }
        if (type == 2 && blen >= 32) {             /* obsolete Packet Block */
            uint16_t ifid = rd16(c, b + 8);
            uint64_t ts = ((uint64_t)rd32(c, b + 12) << 32) | rd32(c, b + 16);
            uint32_t caplen = rd32(c, b + 20), wirelen = rd32(c, b + 24);
            if (ifid >= c->n_if || ifid >= CAP_MAX_IF || 28 + caplen > blen) { c->skipped++; continue; }
            uint64_t div = c->if_tsdiv[ifid];
            p->data = b + 28;
            p->caplen = caplen;
            p->wirelen = wirelen;
            p->ts_ns = (ts / div) * 1000000000ull + (ts % div) * 1000000000ull / div;
            p->linktype = c->if_link[ifid];
            return 1;
        }
        /* SHB, statistics, name resolution, custom...: skip */
    }
}

int cap_next(cap_t *c, cap_pkt_t *p) {
    return c->is_ng ? next_ng(c, p) : next_classic(c, p);
}

void cap_close(cap_t *c) {
    free(c->buf);
    c->buf = NULL;
}
