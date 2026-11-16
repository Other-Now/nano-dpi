#include "dpi.h"
#include <ctype.h>
#include <string.h>

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }

static void copy_host(char *dst, size_t dstsz, const uint8_t *src, size_t n) {
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < dstsz; i++) {
        uint8_t c = src[i];
        if (c < 0x21 || c > 0x7e) c = '?';           /* keep CSV/log output sane */
        dst[j++] = (char)tolower(c);
    }
    dst[j] = 0;
}

/* ------------------------------------------------------------------ HTTP */

static const char *const methods[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE ",
    /* WebDAV (RFC 4918) */
    "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK ", "REPORT ", "SEARCH "};

dpi_res_t dpi_http_host(const uint8_t *d, uint32_t n, char *host, size_t hostsz) {
    int ok = 0;
    for (size_t m = 0; m < sizeof methods / sizeof *methods; m++) {
        size_t ml = strlen(methods[m]);
        size_t cmp = n < ml ? n : ml;
        if (memcmp(d, methods[m], cmp) == 0) {
            if (n < ml) return DPI_NEED_MORE;
            ok = 1;
            break;
        }
    }
    if (!ok) return DPI_NO;
    /* walk header lines */
    uint32_t i = 0;
    while (i < n && d[i] != '\n') i++;                /* skip request line */
    while (i < n) {
        uint32_t ls = ++i;                            /* line start */
        while (i < n && d[i] != '\n') i++;
        if (i >= n) return DPI_NEED_MORE;             /* line not complete yet */
        uint32_t le = i;                              /* points at '\n' */
        if (le > ls && d[le - 1] == '\r') le--;
        if (le == ls) { host[0] = 0; return DPI_MATCH; } /* blank line: end of headers, no Host */
        if (le - ls > 5 && strncasecmp((const char *)d + ls, "host:", 5) == 0) {
            uint32_t v = ls + 5;
            while (v < le && (d[v] == ' ' || d[v] == '\t')) v++;
            uint32_t ve = le;
            while (ve > v && (d[ve - 1] == ' ' || d[ve - 1] == '\t')) ve--;
            /* drop ":port" - "host:8080" and "[2001:db8::1]:8080", but not a bare v6 literal */
            uint32_t pe = ve;
            while (pe > v && d[pe - 1] >= '0' && d[pe - 1] <= '9') pe--;
            if (pe > v + 1 && pe < ve && d[pe - 1] == ':' &&
                (d[v] == '[' ? d[pe - 2] == ']' : !memchr(d + v, ':', pe - 1 - v)))
                ve = pe - 1;
            copy_host(host, hostsz, d + v, ve - v);
            return DPI_MATCH;
        }
    }
    return DPI_NEED_MORE;
}

/* ------------------------------------------------------------------- TLS */

dpi_res_t dpi_tls_handshake_sni(const uint8_t *h, uint32_t n, char *host, size_t hostsz) {
    host[0] = 0;
    if (n < 1) return DPI_NEED_MORE;
    if (h[0] != 1) return DPI_NO;                     /* not a ClientHello */
    if (n < 4) return DPI_NEED_MORE;
    uint32_t mlen = be24(h + 1);
    uint32_t end = 4 + mlen;                          /* message end (may be > n) */
    uint32_t o = 4 + 2 + 32;                          /* legacy_version + random */
    /* past the message end = malformed but still TLS; past the bytes we have = wait */
#define NEED(x) do { if ((x) > end) return DPI_MATCH; if ((x) > n) return DPI_NEED_MORE; } while (0)
    NEED(o + 1);
    o += 1 + h[o];                                    /* session id */
    NEED(o + 2);
    o += 2 + be16(h + o);                             /* cipher suites */
    NEED(o + 1);
    o += 1 + h[o];                                    /* compression methods */
    NEED(o + 2);
    uint32_t ext_end = o + 2 + be16(h + o);
    if (ext_end > end) ext_end = end;
    o += 2;
    while (o + 4 <= ext_end) {
        NEED(o + 4);
        uint16_t et = be16(h + o), el = be16(h + o + 2);
        if (et == 0) {                                /* server_name */
            uint32_t p = o + 4;
            NEED(p + 5);
            /* list_len(2) name_type(1) name_len(2) name */
            uint16_t nl = be16(h + p + 3);
            NEED(p + 5 + nl);
            if (h[p + 2] == 0) copy_host(host, hostsz, h + p + 5, nl);
            return DPI_MATCH;
        }
        o += 4 + el;
    }
    if (o > n) return DPI_NEED_MORE;                  /* extension list not fully seen */
#undef NEED
    return DPI_MATCH;                                 /* ClientHello without SNI */
}

dpi_res_t dpi_tls_sni(const uint8_t *d, uint32_t n, char *host, size_t hostsz) {
    host[0] = 0;
    if (n < 1) return DPI_NEED_MORE;
    if (d[0] != 0x16) return DPI_NO;                  /* handshake record */
    if (n < 3) return DPI_NEED_MORE;
    if (d[1] != 0x03 || d[2] > 0x04) return DPI_NO;
    if (n < 6) return DPI_NEED_MORE;
    if (d[5] != 1) return DPI_NO;                     /* first message must be ClientHello */

    /* gather handshake bytes from consecutive records (a ClientHello may be
     * split across records, and records across segments) */
    uint8_t hs[8192];
    uint32_t hn = 0, o = 0;
    while (o + 5 <= n && d[o] == 0x16 && hn < sizeof hs) {
        uint32_t rl = be16(d + o + 3);
        uint32_t avail = n - (o + 5) < rl ? n - (o + 5) : rl;
        if (avail > sizeof hs - hn) avail = (uint32_t)sizeof hs - hn;
        memcpy(hs + hn, d + o + 5, avail);
        hn += avail;
        if (avail < rl) break;                        /* record continues in a later segment */
        o += 5 + rl;
        if (hn >= 4 && hn >= 4 + be24(hs + 1)) break; /* whole ClientHello collected */
    }
    return dpi_tls_handshake_sni(hs, hn, host, hostsz);
}

/* ------------------------------------------------------------------- DNS */

dpi_res_t dpi_dns_qname(const uint8_t *d, uint32_t n, int tcp, char *host, size_t hostsz) {
    host[0] = 0;
    if (tcp) {
        if (n < 2) return DPI_NEED_MORE;
        d += 2; n -= 2;
    }
    if (n < 12) return tcp ? DPI_NEED_MORE : DPI_NO;
    uint16_t flags = be16(d + 2), qd = be16(d + 4);
    if (((flags >> 11) & 0xf) > 6) return DPI_NO;     /* opcode */
    if (qd == 0 || qd > 16) return DPI_NO;
    uint32_t o = 12, hj = 0;
    for (int labels = 0; labels < 128; labels++) {
        if (o >= n) return tcp ? DPI_NEED_MORE : DPI_NO;
        uint8_t l = d[o];
        if (l == 0) {
            if (hj == 0 && hostsz > 1) { host[0] = '.'; host[1] = 0; } /* root */
            else host[hj] = 0;
            return DPI_MATCH;
        }
        if (l & 0xc0) return DPI_NO;                  /* no compression in a question name */
        if (o + 1 + l > n) return tcp ? DPI_NEED_MORE : DPI_NO;
        if (hj && hj + 1 < hostsz) host[hj++] = '.';
        for (uint32_t i = 0; i < l && hj + 1 < hostsz; i++) {
            uint8_t c = d[o + 1 + i];
            host[hj++] = (char)((c < 0x21 || c > 0x7e) ? '?' : tolower(c));
        }
        host[hj] = 0;
        o += 1u + l;
    }
    return DPI_NO;
}
