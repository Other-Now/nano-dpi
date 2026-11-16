/* test_nanodpi.c - unit + small end-to-end tests. No framework: CHECK() counts. */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "dpi.h"
#include "engine.h"
#include "flow.h"
#include "policer.h"
#include "quic.h"
#include "reasm.h"
#include "rules.h"

static int checks, fails;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void hex(const char *s, uint8_t *out) {
    for (size_t i = 0; s[2 * i]; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
}

/* ------------------------------------------------------------ builders */

/* ClientHello record with a `pad`-byte filler extension placed before
 * (sni_last=1) or after (sni_last=0) the server_name extension. Chrome
 * randomises extension order, and its X25519MLKEM768 key share is ~1.2 KB,
 * so "SNI after a big extension" is the realistic case. */
static uint32_t build_client_hello(uint8_t *o, const char *sni, uint32_t pad, int sni_last, int record) {
    uint8_t ext[4096];
    uint32_t el = 0;
    uint32_t nl = sni ? (uint32_t)strlen(sni) : 0;
    uint8_t sn[300];
    uint32_t snl = 0;
    if (sni) {
        sn[snl++] = 0; sn[snl++] = 0;                       /* type server_name */
        sn[snl++] = (uint8_t)((nl + 5) >> 8); sn[snl++] = (uint8_t)(nl + 5);
        sn[snl++] = (uint8_t)((nl + 3) >> 8); sn[snl++] = (uint8_t)(nl + 3);
        sn[snl++] = 0;
        sn[snl++] = (uint8_t)(nl >> 8); sn[snl++] = (uint8_t)nl;
        memcpy(sn + snl, sni, nl); snl += nl;
    }
    uint8_t pd[2048];
    uint32_t pdl = 0;
    if (pad) {
        pd[pdl++] = 0x00; pd[pdl++] = 0x33;                 /* key_share */
        pd[pdl++] = (uint8_t)(pad >> 8); pd[pdl++] = (uint8_t)pad;
        memset(pd + pdl, 0xab, pad); pdl += pad;
    }
    if (sni_last) { memcpy(ext, pd, pdl); el = pdl; memcpy(ext + el, sn, snl); el += snl; }
    else          { memcpy(ext, sn, snl); el = snl; memcpy(ext + el, pd, pdl); el += pdl; }

    uint8_t body[4200];
    uint32_t b = 0;
    body[b++] = 3; body[b++] = 3;
    memset(body + b, 0x11, 32); b += 32;                     /* random */
    body[b++] = 32; memset(body + b, 0x22, 32); b += 32;     /* session id */
    body[b++] = 0; body[b++] = 2; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 1; body[b++] = 0;
    body[b++] = (uint8_t)(el >> 8); body[b++] = (uint8_t)el;
    memcpy(body + b, ext, el); b += el;

    uint32_t n = 0;
    if (record) { o[n++] = 0x16; o[n++] = 3; o[n++] = 1; o[n++] = (uint8_t)((b + 4) >> 8); o[n++] = (uint8_t)(b + 4); }
    o[n++] = 1; o[n++] = (uint8_t)(b >> 16); o[n++] = (uint8_t)(b >> 8); o[n++] = (uint8_t)b;
    memcpy(o + n, body, b);
    return n + b;
}

/* Ethernet + IPv4 + TCP/UDP frame */
static uint32_t build_frame(uint8_t *o, uint32_t sip, uint32_t dip, uint8_t proto, uint16_t sp, uint16_t dp,
                            uint32_t seq, uint8_t flags, const uint8_t *pl, uint32_t pln) {
    memset(o, 0, 14 + 20 + 20);
    o[12] = 0x08; o[13] = 0x00;
    uint8_t *ip = o + 14;
    uint32_t l4 = proto == 6 ? 20 : 8;
    uint32_t tot = 20 + l4 + pln;
    ip[0] = 0x45; ip[2] = (uint8_t)(tot >> 8); ip[3] = (uint8_t)tot; ip[8] = 64; ip[9] = proto;
    for (int i = 0; i < 4; i++) { ip[12 + i] = (uint8_t)(sip >> (24 - 8 * i)); ip[16 + i] = (uint8_t)(dip >> (24 - 8 * i)); }
    uint8_t *t = ip + 20;
    t[0] = (uint8_t)(sp >> 8); t[1] = (uint8_t)sp; t[2] = (uint8_t)(dp >> 8); t[3] = (uint8_t)dp;
    if (proto == 6) {
        for (int i = 0; i < 4; i++) t[4 + i] = (uint8_t)(seq >> (24 - 8 * i));
        t[12] = 5 << 4; t[13] = flags;
    } else {
        t[4] = (uint8_t)((8 + pln) >> 8); t[5] = (uint8_t)(8 + pln);
    }
    memcpy(t + l4, pl, pln);
    return 14 + tot;
}

static int feed(engine_t *e, const uint8_t *fr, uint32_t n, uint64_t ts) {
    cap_pkt_t cp = {.data = fr, .caplen = n, .wirelen = n, .ts_ns = ts, .linktype = 1};
    return engine_packet(e, &cp);
}

/* ------------------------------------------------------------------ tests */

static void test_reasm(void) {
    reasm_t *r = calloc(1, sizeof *r);
    CHECK(reasm_put(r, 5, (const uint8_t *)"FGHIJ", 5) == 0);     /* hole at 0 */
    CHECK(reasm_put(r, 0, (const uint8_t *)"ABC", 3) == 3);
    CHECK(reasm_put(r, 2, (const uint8_t *)"XDE", 3) == 10);      /* overlap: first writer wins */
    CHECK(memcmp(r->data, "ABCDEFGHIJ", 10) == 0);
    CHECK(reasm_put(r, REASM_CAP + 5, (const uint8_t *)"zz", 2) == 10);
    free(r);
}

static void test_http(void) {
    char h[96];
    const char *req = "GET /x HTTP/1.1\r\nUser-Agent: t\r\nHoSt:  Example.COM:8080 \r\n\r\n";
    CHECK(dpi_http_host((const uint8_t *)req, (uint32_t)strlen(req), h, sizeof h) == DPI_MATCH);
    CHECK(strcmp(h, "example.com") == 0);                        /* port stripped */
    const char *v6 = "GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n";
    CHECK(dpi_http_host((const uint8_t *)v6, (uint32_t)strlen(v6), h, sizeof h) == DPI_MATCH && strcmp(h, "[2001:db8::1]") == 0);
    const char *v6b = "GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n";      /* bare literal: keep */
    CHECK(dpi_http_host((const uint8_t *)v6b, (uint32_t)strlen(v6b), h, sizeof h) == DPI_MATCH && strcmp(h, "2001:db8::1") == 0);
    CHECK(dpi_http_host((const uint8_t *)req, 20, h, sizeof h) == DPI_NEED_MORE);
    CHECK(dpi_http_host((const uint8_t *)"GE", 2, h, sizeof h) == DPI_NEED_MORE);
    CHECK(dpi_http_host((const uint8_t *)"SSH-2.0-x\r\n", 11, h, sizeof h) == DPI_NO);
    const char *nohost = "GET / HTTP/1.0\r\nA: b\r\n\r\n";
    CHECK(dpi_http_host((const uint8_t *)nohost, (uint32_t)strlen(nohost), h, sizeof h) == DPI_MATCH && h[0] == 0);
}

static void test_tls(void) {
    uint8_t ch[4096];
    char h[96];
    uint32_t n = build_client_hello(ch, "www.Example.org", 1216, 1, 1);
    CHECK(dpi_tls_sni(ch, n, h, sizeof h) == DPI_MATCH && strcmp(h, "www.example.org") == 0);
    /* every strict prefix that cuts before the name ends must ask for more */
    int ok = 1;
    for (uint32_t k = 1; k < n - 3; k++) if (dpi_tls_sni(ch, k, h, sizeof h) != DPI_NEED_MORE) { ok = 0; break; }
    CHECK(ok);
    /* SNI first: the first 1460-byte segment is enough */
    n = build_client_hello(ch, "a.b", 1216, 0, 1);
    CHECK(dpi_tls_sni(ch, 200, h, sizeof h) == DPI_MATCH && strcmp(h, "a.b") == 0);
    /* no SNI at all */
    n = build_client_hello(ch, NULL, 40, 0, 1);
    CHECK(dpi_tls_sni(ch, n, h, sizeof h) == DPI_MATCH && h[0] == 0);
    CHECK(dpi_tls_sni((const uint8_t *)"\x17\x03\x03\x00\x10", 5, h, sizeof h) == DPI_NO);
    /* length fields that lie (malformed but complete): must not hang in NEED_MORE */
    n = build_client_hello(ch, "x.y", 0, 0, 1);
    ch[5 + 4 + 34] = 200;                                    /* session id length > message */
    CHECK(dpi_tls_sni(ch, n, h, sizeof h) == DPI_MATCH);
}

static void test_dns(void) {
    uint8_t q[64] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                     3, 'w', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    char h[96];
    CHECK(dpi_dns_qname(q, 33, 0, h, sizeof h) == DPI_MATCH && strcmp(h, "www.example.com") == 0);
    CHECK(dpi_dns_qname(q, 20, 0, h, sizeof h) == DPI_NO);
    uint8_t t[80] = {0, 33};
    memcpy(t + 2, q, 33);
    CHECK(dpi_dns_qname(t, 20, 1, h, sizeof h) == DPI_NEED_MORE);
    CHECK(dpi_dns_qname(t, 35, 1, h, sizeof h) == DPI_MATCH && strcmp(h, "www.example.com") == 0);
}

static void test_quic_keys(void) {
    /* RFC 9001 Appendix A.1 */
    uint8_t dcid[8], key[16], iv[12], hp[16], ek[16], ei[12], eh[16];
    hex("8394c8f03e515708", dcid);
    CHECK(quic_client_keys(1, dcid, 8, key, iv, hp));
    hex("1f369613dd76d5467730efcbe3b1a22d", ek);
    hex("fa044b2f42a3fd3b46fb255c", ei);
    hex("9f50449e04a0e810283a1e9933adedd2", eh);
    CHECK(memcmp(key, ek, 16) == 0);
    CHECK(memcmp(iv, ei, 12) == 0);
    CHECK(memcmp(hp, eh, 16) == 0);
    /* RFC 9369 (QUIC v2) Appendix A.1 */
    CHECK(quic_client_keys(0x6b3343cf, dcid, 8, key, iv, hp));
    hex("8b1a0bc121284290a29e0971b5cd045d", ek);
    hex("91f73e2351d8fa91660e909f", ei);
    hex("45b95e15235d6f45a6b19cbcb0294ba9", eh);
    CHECK(memcmp(key, ek, 16) == 0);
    CHECK(memcmp(iv, ei, 12) == 0);
    CHECK(memcmp(hp, eh, 16) == 0);
    CHECK(!quic_client_keys(0x51303436, dcid, 8, key, iv, hp));   /* gQUIC Q046: unsupported */
}

/* Build a protected client Initial carrying CRYPTO[off, off+len) of `ch`. */
static uint32_t build_quic_initial(uint8_t *o, const uint8_t *dcid, uint32_t pn,
                                   const uint8_t *ch, uint32_t off, uint32_t len) {
    uint8_t key[16], iv[12], hp[16];
    quic_client_keys(1, dcid, 8, key, iv, hp);
    uint8_t pt[1400];
    uint32_t p = 0;
    pt[p++] = 0x06;                                          /* CRYPTO */
    pt[p++] = (uint8_t)(0x40 | off >> 8); pt[p++] = (uint8_t)off;
    pt[p++] = (uint8_t)(0x40 | len >> 8); pt[p++] = (uint8_t)len;
    memcpy(pt + p, ch + off, len); p += len;
    while (p < 1100) pt[p++] = 0;                            /* PADDING */
    uint32_t h = 0;
    o[h++] = 0xc0 | 0x01;                                    /* long, Initial, pn_len 2 */
    o[h++] = 0; o[h++] = 0; o[h++] = 0; o[h++] = 1;
    o[h++] = 8; memcpy(o + h, dcid, 8); h += 8;
    o[h++] = 0;                                              /* SCID len */
    o[h++] = 0;                                              /* token len */
    uint32_t plen = 2 + p + 16;
    o[h++] = (uint8_t)(0x40 | plen >> 8); o[h++] = (uint8_t)plen;
    uint32_t pn_off = h;
    o[h++] = (uint8_t)(pn >> 8); o[h++] = (uint8_t)pn;
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    nonce[10] ^= (uint8_t)(pn >> 8); nonce[11] ^= (uint8_t)pn;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l;
    EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(c, NULL, &l, o, (int)h);
    EVP_EncryptUpdate(c, o + h, &l, pt, (int)p);
    EVP_EncryptFinal_ex(c, o + h + p, &l);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, o + h + p);
    EVP_CIPHER_CTX_free(c);
    /* header protection */
    uint8_t mask[16];
    c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, hp, NULL);
    EVP_CIPHER_CTX_set_padding(c, 0);
    EVP_EncryptUpdate(c, mask, &l, o + pn_off + 4, 16);
    EVP_CIPHER_CTX_free(c);
    o[0] ^= mask[0] & 0x0f;
    o[pn_off] ^= mask[1];
    o[pn_off + 1] ^= mask[2];
    return h + p + 16;
}

static void test_quic_roundtrip(void) {
    uint8_t ch[4096], dg[1500], dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t chn = build_client_hello(ch, "quic.example.net", 1216, 1, 0);  /* bare handshake msg */
    uint32_t half = 900;
    uint8_t sdcid[20], sdl = 0;
    uint32_t ver = 0;
    reasm_t *rb = calloc(1, sizeof *rb);
    char h[96];
    /* second half first: CRYPTO frames out of order across packets */
    uint32_t n = build_quic_initial(dg, dcid, 1, ch, half, chn - half);
    CHECK(quic_inspect(dg, n, sdcid, &sdl, &ver, rb, h, sizeof h) == DPI_NEED_MORE);
    n = build_quic_initial(dg, dcid, 0, ch, 0, half);
    CHECK(quic_inspect(dg, n, sdcid, &sdl, &ver, rb, h, sizeof h) == DPI_MATCH);
    CHECK(strcmp(h, "quic.example.net") == 0);
    /* flip one ciphertext byte: the GCM tag must reject it */
    memset(rb, 0, sizeof *rb);
    sdl = 0;
    n = build_quic_initial(dg, dcid, 0, ch, 0, half);
    dg[n - 30] ^= 1;
    uint64_t fails_before = quic_decrypt_fail;
    CHECK(quic_inspect(dg, n, sdcid, &sdl, &ver, rb, h, sizeof h) == DPI_NO);
    CHECK(quic_decrypt_fail == fails_before + 1);
    free(rb);
}

static void test_tcp_states(void) {
    flow_t f;
    memset(&f, 0, sizeof f);
    tcp_track(&f, 0, TH_SYN);            CHECK(f.state == TCP_SYN_SENT);
    tcp_track(&f, 1, TH_SYN | TH_ACK);   CHECK(f.state == TCP_SYN_RCVD);
    tcp_track(&f, 0, TH_ACK);            CHECK(f.state == TCP_ESTABLISHED);
    tcp_track(&f, 1, TH_FIN | TH_ACK);   CHECK(f.state == TCP_FIN_WAIT);
    tcp_track(&f, 0, TH_ACK);            CHECK(f.state == TCP_FIN_WAIT);
    tcp_track(&f, 0, TH_FIN | TH_ACK);   CHECK(f.state == TCP_LAST_ACK);
    tcp_track(&f, 0, TH_ACK);            CHECK(f.state == TCP_LAST_ACK);   /* wrong side */
    tcp_track(&f, 1, TH_ACK);            CHECK(f.state == TCP_TIME_WAIT);
    CHECK(tcp_is_reopen(&f, 0, TH_SYN));
    memset(&f, 0, sizeof f);
    tcp_track(&f, 0, TH_ACK | TH_PSH);   CHECK(f.state == TCP_ESTABLISHED && f.midstream);
    tcp_track(&f, 1, TH_RST);            CHECK(f.state == TCP_CLOSE);
    memset(&f, 0, sizeof f);
    tcp_track(&f, 0, TH_SYN);
    tcp_track(&f, 1, TH_RST | TH_ACK);   CHECK(f.state == TCP_CLOSE);      /* refused */
}

/* random insert/expire against a brute-force reference */
static void test_flow_table(void) {
    ftab_t t;
    ftab_init(&t, 1024);
    uint64_t ts[700] = {0};
    int ok = 1;
    srand(7);
    for (int round = 0; round < 20; round++) {
        uint64_t now = (uint64_t)round * 10 * 1000000000ull;
        for (int i = 0; i < 700; i++) {
            if (rand() % 3) continue;
            pkt_t p = {.ipver = 4, .proto = 17, .sport = (uint16_t)(1000 + i), .dport = 53, .ts_ns = now};
            p.src[0] = 10; p.dst[0] = 8;
            int dir, cr;
            flow_t *f = ftab_get(&t, &p, &dir, &cr);
            if (!f) { ok = 0; break; }
            if (cr != (ts[i] == 0)) ok = 0;
            f->last_ns = now;
            ftab_touch(&t, f);
            ts[i] = now + 1;
        }
        ftab_expire(&t, now, NULL, NULL);          /* udp timeout 30 s */
        for (int i = 0; i < 700; i++)
            if (ts[i] && now - (ts[i] - 1) > 30ull * 1000000000ull) ts[i] = 0;
        uint32_t live = 0;
        for (int i = 0; i < 700; i++) live += ts[i] != 0;
        if (live != t.n) ok = 0;
    }
    CHECK(ok);
    ftab_free(&t);
}

static void test_rules_equivalence(void) {
    ruleset_t rs;
    rules_init(&rs);
    srand(42);
    static const uint8_t lens[] = {0, 8, 16, 24, 32};
    static const uint16_t ports[] = {0, 0, 0, 53, 80, 443, 8080, 22};
    for (int i = 0; i < 5000; i++) {
        rule_t r = {0};
        r.slen = lens[rand() % 5]; r.dlen = lens[rand() % 5];
        r.src = (uint32_t)(10u << 24 | (rand() & 0xff) << 16 | (rand() & 3) << 8 | (rand() & 3));
        r.dst = (uint32_t)(172u << 24 | (rand() & 0xff) << 16 | (rand() & 3) << 8 | (rand() & 3));
        r.proto = (uint8_t)(rand() % 3 == 0 ? 0 : rand() % 2 ? 6 : 17);
        r.dport = ports[rand() % 8];
        r.sport = rand() % 10 == 0 ? (uint16_t)(1024 + rand() % 4) : 0;
        r.app = rand() % 4 == 0 ? (uint16_t)(1 + rand() % 5) : 0;
        r.action = (uint8_t)(rand() % 2);
        rules_add(&rs, &r);
    }
    rules_build_tss(&rs);
    int same = 1, hits = 0;
    for (int i = 0; i < 200000; i++) {
        const rule_t *r = &rs.r[rand() % rs.n];               /* aim near real rules */
        rkey_t k = {.src = r->src | (uint32_t)(rand() & 3), .dst = r->dst | (uint32_t)(rand() & 3),
                    .proto = (uint8_t)(rand() % 2 ? 6 : 17), .sport = (uint16_t)(1024 + rand() % 4),
                    .dport = ports[rand() % 8], .app = (uint16_t)(rand() % 6), .v6 = rand() % 50 == 0};
        int a = rules_match_linear(&rs, &k), b = rules_match_tss(&rs, &k);
        if (a != b) { same = 0; fprintf(stderr, "mismatch at key %d: linear %d tss %d\n", i, a, b); break; }
        hits += a >= 0;
    }
    CHECK(same);
    CHECK(hits > 1000);
    rules_free(&rs);
}

static void test_policer(void) {
    /* offer 2x CIR for 10 s, 1000-byte packets */
    srtcm_cfg_t c = {.cir_Bps = 1250000, .cbs = 20000, .ebs = 40000};   /* 10 Mbit/s */
    srtcm_t m;
    srtcm_init(&m, &c);
    uint64_t passed = 0, red = 0;
    uint64_t gap_ns = 1000ull * 1000000000ull / (2 * c.cir_Bps);        /* 400 us */
    uint64_t T = 10ull * 1000000000ull;
    for (uint64_t t = 0; t < T; t += gap_ns) {
        int col = srtcm_color(&m, &c, t, 1000);
        if (col == POL_RED) red++; else passed += 1000;
    }
    uint64_t expect = c.cir_Bps * 10 + c.cbs + c.ebs;
    CHECK(passed <= expect && passed + 1000 >= expect);
    CHECK(red > 0);
    /* under-rate traffic is never red */
    srtcm_init(&m, &c);
    int anyred = 0;
    for (uint64_t t = 0; t < T; t += 4 * gap_ns) anyred |= srtcm_color(&m, &c, t, 1000) == POL_RED;
    CHECK(!anyred);
}

static void test_apps(void) {
    apps_t a;
    apps_init(&a);
    uint16_t app;
    uint8_t cat;
    apps_classify(&a, "rr3---sn-abc.googlevideo.com", &app, &cat);
    CHECK(app == apps_app_id("youtube") && cat == apps_cat_id(&a, "streaming"));
    apps_classify(&a, "teams.microsoft.com", &app, &cat);
    CHECK(app == apps_app_id("teams"));
    apps_classify(&a, "www.microsoft.com:443", &app, &cat);
    CHECK(app == apps_app_id("microsoft"));
    apps_classify(&a, "example.invalid", &app, &cat);
    CHECK(app == 0 && cat == 0);
    apps_free(&a);
}

/* ClientHello split over two TCP segments that arrive out of order. */
static void run_split_hello(int reasm, char *host_out) {
    engine_t e;
    engine_init(&e, 1024, NULL, NULL);
    e.reasm = reasm;
    uint8_t ch[4096], fr[2000];
    uint32_t chn = build_client_hello(ch, "split.example.com", 1216, 1, 1);
    uint32_t C = 0x0a000001, S = 0x5db8d822, isn = 1000;
    uint32_t n;
    n = build_frame(fr, C, S, 6, 40000, 443, isn, TH_SYN, NULL, 0);           feed(&e, fr, n, 1);
    n = build_frame(fr, S, C, 6, 443, 40000, 5000, TH_SYN | TH_ACK, NULL, 0); feed(&e, fr, n, 2);
    n = build_frame(fr, C, S, 6, 40000, 443, isn + 1, TH_ACK, NULL, 0);       feed(&e, fr, n, 3);
    uint32_t mss = 1000;
    n = build_frame(fr, C, S, 6, 40000, 443, isn + 1 + mss, TH_ACK | TH_PSH, ch + mss, chn - mss); feed(&e, fr, n, 4);
    n = build_frame(fr, C, S, 6, 40000, 443, isn + 1, TH_ACK, ch, mss);       feed(&e, fr, n, 5);
    flow_t *f = NULL;
    for (uint32_t i = 0; i < e.ft.cap; i++) if (e.ft.slots[i].used) f = &e.ft.slots[i];
    strcpy(host_out, f ? f->host : "?");
    CHECK(f && f->state == TCP_ESTABLISHED && f->pkts[0] == 4 && f->pkts[1] == 1);
    engine_free(&e);
}

static void test_engine_reassembly(void) {
    char h[96];
    run_split_hello(1, h);
    CHECK(strcmp(h, "split.example.com") == 0);
    run_split_hello(0, h);
    CHECK(h[0] == 0);                         /* per-packet parsing cannot see it */
}

static void test_engine_firewall(void) {
    apps_t a;
    apps_init(&a);
    ruleset_t rs;
    rules_init(&rs);
    CHECK(rules_parse_line(&rs, &a, "policer slow cir=80k cbs=3000 ebs=0") == 0);
    CHECK(rules_parse_line(&rs, &a, "drop dst=10.9.0.0/16") == 0);
    CHECK(rules_parse_line(&rs, &a, "police=slow app=youtube") == 0);
    CHECK(rules_parse_line(&rs, &a, "# comment") == 1);
    CHECK(rules_parse_line(&rs, &a, "drop app=nosuchapp") < 0);
    rules_build_tss(&rs);
    engine_t e;
    engine_init(&e, 1024, &a, &rs);
    uint8_t ch[4096], fr[2000];
    uint32_t chn = build_client_hello(ch, "rr1.googlevideo.com", 100, 1, 1), n;
    n = build_frame(fr, 0x0a000002, 0x0a090001, 17, 5000, 53, 0, 0, ch, 10);
    CHECK(feed(&e, fr, n, 1) == ACT_DROP);                        /* L3 drop from the first packet */
    n = build_frame(fr, 0x0a000002, 0x8efa0001, 6, 41000, 443, 1, TH_ACK | TH_PSH, ch, chn);
    feed(&e, fr, n, 2);                                           /* DPI names it youtube */
    int drops = 0;
    for (int i = 0; i < 100; i++) {                               /* 100 x 1000 B in 10 ms >> 80 kbit/s */
        n = build_frame(fr, 0x8efa0001, 0x0a000002, 6, 443, 41000, 9, TH_ACK, ch, 946);
        drops += feed(&e, fr, n, 3 + (uint64_t)i * 100000) == ACT_DROP;
    }
    CHECK(drops >= 95);
    CHECK(e.st.fw_evals == 3);                                    /* 2 flows created + 1 re-eval after DPI */
    engine_free(&e);
    rules_free(&rs);
    apps_free(&a);
}

int main(void) {
    test_reasm();
    test_http();
    test_tls();
    test_dns();
    test_quic_keys();
    test_quic_roundtrip();
    test_tcp_states();
    test_flow_table();
    test_rules_equivalence();
    test_policer();
    test_apps();
    test_engine_reassembly();
    test_engine_firewall();
    printf("%d checks, %d failed\n", checks, fails);
    return fails != 0;
}
