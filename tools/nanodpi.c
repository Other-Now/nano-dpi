/* nanodpi - run the DPI/firewall engine over pcap/pcapng files.
 *
 *   nanodpi [-o flows.csv] [-R rules.txt] [-C cat:feedfile]... [-n] [-L]
 *           [-F flow_capacity] [-b reps] file...
 *
 *   -o  write one CSV row per flow (when it expires, is reused, or at the end)
 *   -R  firewall rules + policers (see rules.h for the syntax)
 *   -C  load a domain feed as content category `cat` (e.g. malware:urlhaus.rpz)
 *   -n  no reassembly: parse every client packet on its own (naive DPI)
 *   -L  linear rule scan instead of tuple-space search
 *   -F  flow table slots (rounded up to a power of two), default 262144
 *   -S  expiry sweep period in ms of trace time (default 1000, 0 = never)
 *   -b  benchmark: load every packet into memory, run the engine `reps`
 *       times on a fresh table, report packets/s for the fastest and median rep
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "engine.h"
#include "quic.h"

static void fmt_ep(char *out, size_t sz, int ipver, const uint8_t *a, uint16_t port) {
    char ip[INET6_ADDRSTRLEN];
    if (ipver == 4) { inet_ntop(AF_INET, a, ip, sizeof ip); snprintf(out, sz, "%s:%u", ip, port); }
    else            { inet_ntop(AF_INET6, a, ip, sizeof ip); snprintf(out, sz, "[%s]:%u", ip, port); }
}

typedef struct { FILE *csv; apps_t *apps; uint64_t closed[TCP_NSTATES]; } out_ctx_t;

static void on_close(flow_t *f, void *vctx) {
    out_ctx_t *o = vctx;
    o->closed[f->state]++;
    if (!o->csv) return;
    char c[64], s[64];
    if (f->client_is_a) { fmt_ep(c, sizeof c, f->k.ipver, f->k.a, f->k.ap); fmt_ep(s, sizeof s, f->k.ipver, f->k.b, f->k.bp); }
    else                { fmt_ep(c, sizeof c, f->k.ipver, f->k.b, f->k.bp); fmt_ep(s, sizeof s, f->k.ipver, f->k.a, f->k.ap); }
    static const char *const act[] = {"allow", "drop", "police"};
    fprintf(o->csv, "%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%d,%u,%u,%u,%llu,%llu,%.6f,%.6f\n",
            f->k.proto == 6 ? "TCP" : f->k.proto == 17 ? "UDP" : "OTHER", c, s,
            f->k.proto == 6 ? tcp_state_name[f->state] : "-", f->midstream,
            l7_name[f->l7], f->host, apps_app_name(f->app),
            o->apps ? apps_cat_name(o->apps, f->cat) : "none", act[f->verdict], f->rule, f->dpi_pkts,
            f->pkts[0], f->pkts[1], (unsigned long long)f->bytes[0], (unsigned long long)f->bytes[1],
            f->first_ns / 1e9, f->last_ns / 1e9);
}

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void print_stats(const engine_t *e, const out_ctx_t *o, const ruleset_t *rs) {
    printf("packets=%llu bytes=%llu not_ip=%llu truncated=%llu fragments=%llu other_l4=%llu untracked=%llu\n",
           (unsigned long long)e->st.pkts, (unsigned long long)e->st.bytes,
           (unsigned long long)e->st.not_ip, (unsigned long long)e->st.trunc,
           (unsigned long long)e->st.frag, (unsigned long long)e->st.other_l4,
           (unsigned long long)e->st.untracked);
    printf("flows_created=%llu flows_expired=%llu flows_reopened=%llu peak_live_flows=%u table_full_drops=%llu "
           "table_slots=%u flow_bytes=%zu trace_seconds=%.1f\n",
           (unsigned long long)e->ft.created, (unsigned long long)e->ft.expired,
           (unsigned long long)e->ft.reopened, e->ft.peak, (unsigned long long)e->ft.full_drops,
           e->ft.cap, sizeof(flow_t), (e->last_ts_ns - e->first_ts_ns) / 1e9);
    printf("l7:");
    for (int i = 0; i < L7_N; i++) printf(" %s=%llu", l7_name[i], (unsigned long long)e->st.l7[i]);
    printf(" with_host=%llu quic_decrypt_ok=%llu quic_decrypt_fail=%llu\n",
           (unsigned long long)e->st.with_host, (unsigned long long)quic_decrypt_ok,
           (unsigned long long)quic_decrypt_fail);
    printf("tcp_state_at_close:");
    for (int i = 1; i < TCP_NSTATES; i++) printf(" %s=%llu", tcp_state_name[i], (unsigned long long)o->closed[i]);
    printf("\n");
    if (rs && rs->n)
        printf("rules=%u tss_shapes=%u fw_evals=%llu drop_pkts=%llu drop_bytes=%llu green=%llu yellow=%llu red=%llu\n",
               rs->n, rs->nshapes, (unsigned long long)e->st.fw_evals,
               (unsigned long long)e->st.drop_pkts, (unsigned long long)e->st.drop_bytes,
               (unsigned long long)e->st.pol[0], (unsigned long long)e->st.pol[1],
               (unsigned long long)e->st.pol[2]);
}

int main(int argc, char **argv) {
    const char *csv_path = NULL, *rules_path = NULL;
    const char *feeds[16];
    int nfeeds = 0, reasm = 1, tss = 1, reps = 0;
    uint32_t cap = 262144;
    long sweep_ms = 1000;
    int opt;
    while ((opt = getopt(argc, argv, "o:R:C:nLF:S:b:")) != -1) {
        switch (opt) {
        case 'o': csv_path = optarg; break;
        case 'R': rules_path = optarg; break;
        case 'C': if (nfeeds < 16) feeds[nfeeds++] = optarg; break;
        case 'n': reasm = 0; break;
        case 'L': tss = 0; break;
        case 'F': cap = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'S': sweep_ms = atol(optarg); break;
        case 'b': reps = atoi(optarg); break;
        default:
            fprintf(stderr, "usage: %s [-o csv] [-R rules] [-C cat:file] [-n] [-L] [-F cap] [-b reps] file...\n", argv[0]);
            return 2;
        }
    }
    if (optind >= argc) { fprintf(stderr, "no input files\n"); return 2; }

    apps_t apps;
    if (apps_init(&apps)) return 1;
    for (int i = 0; i < nfeeds; i++) {
        char buf[512];
        snprintf(buf, sizeof buf, "%s", feeds[i]);
        char *colon = strchr(buf, ':');
        if (!colon) { fprintf(stderr, "-C wants cat:file\n"); return 2; }
        *colon = 0;
        int n = apps_load_feed(&apps, buf, colon + 1);
        if (n < 0) return 1;
        fprintf(stderr, "feed %s: %d domains\n", buf, n);
    }
    ruleset_t rs;
    rules_init(&rs);
    if (rules_path && rules_load(&rs, &apps, rules_path)) return 1;

    out_ctx_t o = {.apps = &apps};
    if (csv_path) {
        o.csv = fopen(csv_path, "w");
        if (!o.csv) { perror(csv_path); return 1; }
        fprintf(o.csv, "proto,client,server,tcp_state,midstream,l7,host,app,category,verdict,rule,dpi_pkts,"
                       "c2s_pkts,s2c_pkts,c2s_bytes,s2c_bytes,first_ts,last_ts\n");
    }

    int nf = argc - optind;
    cap_t *caps = calloc((size_t)nf, sizeof *caps);
    engine_t e;

    if (!reps) {                                     /* normal: stream through files */
        if (engine_init(&e, cap, &apps, &rs)) { fprintf(stderr, "out of memory\n"); return 1; }
        e.reasm = reasm; e.use_tss = tss; e.sweep_ns = (uint64_t)sweep_ms * 1000000ull; e.on_close = on_close; e.ctx = &o;
        for (int i = 0; i < nf; i++) {
            if (cap_open(&caps[i], argv[optind + i])) continue;
            cap_pkt_t cp;
            int r;
            while ((r = cap_next(&caps[i], &cp)) == 1) engine_packet(&e, &cp);
            if (r < 0) fprintf(stderr, "%s: malformed, stopped early\n", argv[optind + i]);
            if (caps[i].skipped) fprintf(stderr, "%s: %llu packets skipped (no interface)\n",
                                         argv[optind + i], (unsigned long long)caps[i].skipped);
            cap_close(&caps[i]);
        }
        engine_finish(&e);
        print_stats(&e, &o, &rs);
        engine_free(&e);
    } else {                                         /* benchmark: in-memory replay */
        size_t np = 0, cp_cap = 1 << 16;
        cap_pkt_t *pk = malloc(cp_cap * sizeof *pk);
        for (int i = 0; i < nf; i++) {
            if (cap_open(&caps[i], argv[optind + i])) continue;
            cap_pkt_t cp;
            while (cap_next(&caps[i], &cp) == 1) {
                if (np == cp_cap) pk = realloc(pk, (cp_cap *= 2) * sizeof *pk);
                pk[np++] = cp;
            }
        }
        double *t = calloc((size_t)reps, sizeof *t);
        for (int r = 0; r < reps; r++) {
            if (engine_init(&e, cap, &apps, &rs)) { fprintf(stderr, "out of memory\n"); return 1; }
            e.reasm = reasm; e.use_tss = tss; e.sweep_ns = (uint64_t)sweep_ms * 1000000ull;
            e.on_close = r == reps - 1 ? on_close : NULL; e.ctx = &o;
            double t0 = now_s();
            for (size_t j = 0; j < np; j++) engine_packet(&e, &pk[j]);
            t[r] = now_s() - t0;
            if (r == reps - 1) { engine_finish(&e); print_stats(&e, &o, &rs); }
            engine_free(&e);
        }
        qsort(t, (size_t)reps, sizeof *t, cmp_d);
        printf("bench packets=%zu reps=%d best_s=%.4f median_s=%.4f best_mpps=%.3f median_mpps=%.3f ns_per_pkt_median=%.1f\n",
               np, reps, t[0], t[reps / 2], np / t[0] / 1e6, np / t[reps / 2] / 1e6, t[reps / 2] * 1e9 / (double)np);
        for (int i = 0; i < nf; i++) cap_close(&caps[i]);
        free(pk);
        free(t);
    }
    if (o.csv) fclose(o.csv);
    free(caps);
    rules_free(&rs);
    apps_free(&apps);
    return 0;
}
