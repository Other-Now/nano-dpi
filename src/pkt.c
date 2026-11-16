#include "pkt.h"
#include <string.h>

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static pkt_status_t parse_l4(const uint8_t *d, uint32_t len, pkt_t *p) {
    if (p->proto == 6) {
        if (len < 20) return PKT_TRUNC;
        uint32_t hl = (uint32_t)(d[12] >> 4) * 4;
        if (hl < 20 || hl > len) return PKT_TRUNC;
        p->sport = be16(d);
        p->dport = be16(d + 2);
        p->seq = be32(d + 4);
        p->ack = be32(d + 8);
        p->tcp_flags = d[13];
        p->payload = d + hl;
        p->paylen = len - hl;
        return PKT_OK;
    }
    if (p->proto == 17) {
        if (len < 8) return PKT_TRUNC;
        p->sport = be16(d);
        p->dport = be16(d + 2);
        uint32_t ulen = be16(d + 4);
        p->payload = d + 8;
        p->paylen = len - 8;
        if (ulen >= 8 && ulen - 8 < p->paylen) p->paylen = ulen - 8; /* strip Ethernet padding */
        return PKT_OK;
    }
    return PKT_OTHER_L4;
}

/* depth: 0 = outer header; 6in4 / 4in6 / IPIP tunnels are unwrapped once */
static pkt_status_t parse_ip(const uint8_t *d, uint32_t len, pkt_t *p, int depth) {
    if (len < 1) return PKT_TRUNC;
    int v = d[0] >> 4;
    if (v == 4) {
        if (len < 20) return PKT_TRUNC;
        uint32_t hl = (uint32_t)(d[0] & 0x0f) * 4;
        if (hl < 20 || hl > len) return PKT_TRUNC;
        uint32_t tot = be16(d + 2);
        if (tot >= hl && tot < len) len = tot;        /* strip L2 padding */
        p->ipver = 4;
        p->proto = d[9];
        memcpy(p->src, d + 12, 4);
        memcpy(p->dst, d + 16, 4);
        uint16_t frag = be16(d + 6);
        if (frag & 0x1fff) return PKT_FRAG;           /* non-first fragment: no L4 header */
        if ((p->proto == 4 || p->proto == 41) && depth == 0 && !(frag & 0x2000))
            return parse_ip(d + hl, len - hl, p, 1);
        pkt_status_t s = parse_l4(d + hl, len - hl, p);
        if (s == PKT_OK && (frag & 0x2000)) return PKT_FRAG; /* first fragment: L4 incomplete */
        return s;
    }
    if (v == 6) {
        if (len < 40) return PKT_TRUNC;
        p->ipver = 6;
        memcpy(p->src, d + 8, 16);
        memcpy(p->dst, d + 24, 16);
        uint32_t plen = be16(d + 4);
        if (40 + plen < len) len = 40 + plen;
        uint8_t nh = d[6];
        uint32_t off = 40;
        /* walk extension headers */
        for (int i = 0; i < 8; i++) {
            if (nh == 0 || nh == 43 || nh == 60) {    /* hop-by-hop, routing, dest opts */
                if (off + 8 > len) return PKT_TRUNC;
                uint32_t el = ((uint32_t)d[off + 1] + 1) * 8;
                nh = d[off];
                off += el;
                if (off > len) return PKT_TRUNC;
            } else if (nh == 44) {                    /* fragment header */
                if (off + 8 > len) return PKT_TRUNC;
                uint16_t fo = be16(d + off + 2);
                p->proto = d[off];
                if ((fo & 0xfff8) || (fo & 1)) return PKT_FRAG;
                nh = d[off];
                off += 8;
            } else break;
        }
        p->proto = nh;
        if ((nh == 4 || nh == 41) && depth == 0) return parse_ip(d + off, len - off, p, 1);
        return parse_l4(d + off, len - off, p);
    }
    return PKT_NOT_IP;
}

pkt_status_t pkt_parse(const uint8_t *d, uint32_t caplen, uint32_t wirelen,
                       int linktype, uint64_t ts_ns, pkt_t *p) {
    memset(p, 0, sizeof *p);
    p->wirelen = wirelen;
    p->ts_ns = ts_ns;
    uint32_t off = 0;
    uint16_t et;

    switch (linktype) {
    case 1:                                           /* Ethernet */
        if (caplen < 14) return PKT_TRUNC;
        et = be16(d + 12);
        off = 14;
        while (et == 0x8100 || et == 0x88a8 || et == 0x9100) { /* VLAN / QinQ */
            if (off + 4 > caplen) return PKT_TRUNC;
            et = be16(d + off + 2);
            off += 4;
        }
        if (et == 0x8864) {                           /* PPPoE session */
            if (off + 8 > caplen) return PKT_TRUNC;
            uint16_t ppp = be16(d + off + 6);
            off += 8;
            et = ppp == 0x0021 ? 0x0800 : ppp == 0x0057 ? 0x86dd : 0;
        }
        if (et != 0x0800 && et != 0x86dd) return PKT_NOT_IP;
        break;
    case 113:                                         /* Linux cooked (SLL) */
        if (caplen < 16) return PKT_TRUNC;
        et = be16(d + 14);
        if (et != 0x0800 && et != 0x86dd) return PKT_NOT_IP;
        off = 16;
        break;
    case 276:                                         /* Linux cooked v2 */
        if (caplen < 20) return PKT_TRUNC;
        et = be16(d);
        if (et != 0x0800 && et != 0x86dd) return PKT_NOT_IP;
        off = 20;
        break;
    case 9: case 50: {                                /* PPP, PPP-in-HDLC */
        if (caplen < 2) return PKT_TRUNC;
        if (d[0] == 0xff && d[1] == 0x03) off = 2;    /* address + control */
        if (off + 2 > caplen) return PKT_TRUNC;
        uint16_t pp = be16(d + off);
        off += 2;
        if (pp != 0x0021 && pp != 0x0057) return PKT_NOT_IP;
        break;
    }
    case 0: case 108:                                 /* BSD loopback: 4-byte AF */
        if (caplen < 4) return PKT_TRUNC;
        off = 4;
        break;
    case 12: case 14: case 101: case 228: case 229:   /* raw IP */
        off = 0;
        break;
    default:
        return PKT_NOT_IP;
    }
    return parse_ip(d + off, caplen - off, p, 0);
}
