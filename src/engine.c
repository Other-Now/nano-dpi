#include "engine.h"
#include <stdlib.h>
#include <string.h>
#include "dpi.h"
#include "quic.h"

int engine_init(engine_t *e, uint32_t flow_cap, apps_t *apps, ruleset_t *rs) {
    memset(e, 0, sizeof *e);
    e->apps = apps;
    e->rs = rs;
    e->reasm = 1;
    e->use_tss = 1;
    e->sweep_ns = 1000000000ull;
    return ftab_init(&e->ft, flow_cap);
}

void engine_free(engine_t *e) {
    ftab_free(&e->ft);
    polmap_free(&e->pm);
}

static inline uint32_t v4(const uint8_t *a) {
    return (uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] << 8 | a[3];
}

/* client/server view of a flow's key */
static void endpoints(const flow_t *f, const uint8_t **cli, uint16_t *cport,
                      const uint8_t **srv, uint16_t *sport) {
    if (f->client_is_a) { *cli = f->k.a; *cport = f->k.ap; *srv = f->k.b; *sport = f->k.bp; }
    else                { *cli = f->k.b; *cport = f->k.bp; *srv = f->k.a; *sport = f->k.ap; }
}

static void classify(engine_t *e, flow_t *f) {
    if (!e->rs || !e->rs->n) return;
    const uint8_t *cli, *srv;
    uint16_t cp, sp;
    endpoints(f, &cli, &cp, &srv, &sp);
    rkey_t k = {
        .src = f->k.ipver == 4 ? v4(cli) : 0, .dst = f->k.ipver == 4 ? v4(srv) : 0,
        .v6 = f->k.ipver == 6, .proto = f->k.proto, .cat = f->cat,
        .sport = cp, .dport = sp, .app = f->app};
    int i = e->use_tss ? rules_match_tss(e->rs, &k) : rules_match_linear(e->rs, &k);
    e->st.fw_evals++;
    f->rule = i;
    f->verdict = i >= 0 ? e->rs->r[i].action : ACT_ALLOW;
    f->policer = i >= 0 && f->verdict == ACT_POLICE ? e->rs->r[i].policer : 0;
}

static void dpi_done(engine_t *e, flow_t *f) {
    f->dpi_done = 1;
    if (f->l7 == L7_UNKNOWN) f->host[0] = 0;    /* a parser that bailed may have left a partial name */
    free(f->rb);
    f->rb = NULL;
    if (f->host[0]) {
        e->st.with_host++;
        if (e->apps) apps_classify(e->apps, f->host, &f->app, &f->cat);
    }
    e->st.l7[f->l7]++;
    if (e->rs && e->rs->uses_l7 && (f->app || f->cat)) classify(e, f);   /* re-decide with L7 info */
}

static int ensure_rb(flow_t *f) {
    if (!f->rb) f->rb = calloc(1, sizeof *f->rb);
    return f->rb != NULL;
}

static void inspect(engine_t *e, flow_t *f, int dir, const pkt_t *p) {
    const uint8_t *cli, *srv;
    uint16_t cp, sp;
    endpoints(f, &cli, &cp, &srv, &sp);
    (void)cli; (void)srv;
    dpi_res_t r = DPI_NO;

    if (f->k.proto == 17) {
        if (sp == 53 || cp == 53) {                       /* DNS: either direction */
            r = dpi_dns_qname(p->payload, p->paylen, 0, f->host, sizeof f->host);
            if (r == DPI_MATCH) f->l7 = L7_DNS;
            dpi_done(e, f);
            return;
        }
        if (dir != 0) return;
        if (++f->dpi_pkts > DPI_MAX_PKTS || !ensure_rb(f)) { dpi_done(e, f); return; }
        r = quic_inspect(p->payload, p->paylen, f->qdcid, &f->qdcid_len, &f->qversion,
                         f->rb, f->host, sizeof f->host);
        if (r != DPI_NO) f->l7 = L7_QUIC;
        if (r == DPI_MATCH || (r == DPI_NO && f->l7 != L7_QUIC && f->dpi_pkts >= 3)) dpi_done(e, f);
        return;
    }

    /* TCP: only client->server bytes */
    if (dir != 0) return;
    if (++f->dpi_pkts > DPI_MAX_PKTS) { dpi_done(e, f); return; }
    const uint8_t *buf = p->payload;
    uint32_t n = p->paylen;
    if (e->reasm) {
        if (!ensure_rb(f)) { dpi_done(e, f); return; }
        if (!f->isn_valid) { f->isn = p->seq; f->isn_valid = 1; }   /* mid-stream pickup */
        uint32_t off = p->seq - f->isn;                             /* wraps correctly */
        if (off >= REASM_CAP) return;                               /* far ahead, or before isn */
        reasm_put(f->rb, off, p->payload, p->paylen);
        buf = f->rb->data;
        n = f->rb->contig;
        if (n == 0) return;                                         /* hole at the start */
    }
    if (sp == 53 || cp == 53) {
        r = dpi_dns_qname(buf, n, 1, f->host, sizeof f->host);
        if (r == DPI_MATCH) f->l7 = L7_DNS;
    } else {
        dpi_res_t rh = dpi_http_host(buf, n, f->host, sizeof f->host);
        if (rh == DPI_MATCH) f->l7 = L7_HTTP;
        dpi_res_t rt = rh == DPI_MATCH ? DPI_NO : dpi_tls_sni(buf, n, f->host, sizeof f->host);
        if (rt == DPI_MATCH) f->l7 = L7_TLS;
        r = rh == DPI_MATCH || rt == DPI_MATCH ? DPI_MATCH
          : rh == DPI_NEED_MORE || rt == DPI_NEED_MORE ? DPI_NEED_MORE : DPI_NO;
        if (r == DPI_NEED_MORE && rt == DPI_NEED_MORE && rh != DPI_NEED_MORE) f->l7 = L7_TLS;
    }
    if (r != DPI_NEED_MORE) dpi_done(e, f);
    else if (e->reasm && f->rb->contig >= REASM_CAP) dpi_done(e, f);
}

/* every flow leaves through here: finish DPI bookkeeping, then report it */
static void close_flow(flow_t *f, void *ctx) {
    engine_t *e = ctx;
    if (!f->dpi_done) dpi_done(e, f);
    if (e->on_close) e->on_close(f, e->ctx);
}

static void sweep(engine_t *e, uint64_t now) {
    if (!e->sweep_ns || now < e->last_sweep_ns + e->sweep_ns) return;
    if (e->last_sweep_ns) ftab_expire(&e->ft, now, close_flow, e);
    e->last_sweep_ns = now;
}

int engine_packet(engine_t *e, const cap_pkt_t *cp) {
    pkt_t p;
    e->st.pkts++;
    e->st.bytes += cp->wirelen;
    pkt_status_t s = pkt_parse(cp->data, cp->caplen, cp->wirelen, cp->linktype, cp->ts_ns, &p);
    switch (s) {
    case PKT_OK: break;
    case PKT_NOT_IP: e->st.not_ip++; return ACT_ALLOW;
    case PKT_TRUNC: e->st.trunc++; return ACT_ALLOW;
    case PKT_FRAG: e->st.frag++; return ACT_ALLOW;
    case PKT_OTHER_L4: e->st.other_l4++; return ACT_ALLOW;
    }
    if (!e->first_ts_ns) e->first_ts_ns = p.ts_ns;
    if (p.ts_ns > e->last_ts_ns) e->last_ts_ns = p.ts_ns;
    sweep(e, p.ts_ns);

    int dir, created;
    flow_t *f = ftab_get(&e->ft, &p, &dir, &created);
    if (!f) { e->st.untracked++; return ACT_ALLOW; }      /* table full: fail open, counted */

    if (p.proto == 6) {
        if (!created && tcp_is_reopen(f, dir, p.tcp_flags)) {
            /* port reuse: SYN on a closed flow starts a new connection */
            close_flow(f, e);
            int client_was_a = f->client_is_a;
            flow_reset(f);
            f->client_is_a = (uint8_t)(dir == 0 ? client_was_a : !client_was_a);
            f->first_ns = p.ts_ns;
            dir = 0;
            created = 1;
            e->ft.reopened++;
        }
        if (dir == 0 && (p.tcp_flags & TH_SYN) && !(p.tcp_flags & TH_ACK)) {
            f->isn = p.seq + 1;                            /* client data starts at ISN+1 */
            f->isn_valid = 1;
        }
        tcp_track(f, dir, p.tcp_flags);
    }
    f->last_ns = p.ts_ns;
    ftab_touch(&e->ft, f);
    f->pkts[dir]++;
    f->bytes[dir] += p.wirelen;

    if (created) classify(e, f);
    if (!f->dpi_done && p.paylen) inspect(e, f, dir, &p);

    int v = f->verdict;
    if (v == ACT_POLICE) {
        const uint8_t *cli, *srv;
        uint16_t a, b;
        endpoints(f, &cli, &a, &srv, &b);
        srtcm_t *m = polmap_get(&e->pm, f->policer, cli, &e->rs->pol[f->policer - 1]);
        int c = m ? srtcm_color(m, &e->rs->pol[f->policer - 1], p.ts_ns, p.wirelen) : POL_GREEN;
        e->st.pol[c]++;
        e->st.pol_bytes[c] += p.wirelen;
        v = c == POL_RED ? ACT_DROP : ACT_ALLOW;
    }
    if (v == ACT_DROP) { e->st.drop_pkts++; e->st.drop_bytes += p.wirelen; }
    return v;
}

void engine_finish(engine_t *e) {
    ftab_foreach(&e->ft, close_flow, e);
}
