/* bench_rules - linear scan vs tuple-space search as the rule count grows.
 *
 * Two rule profiles:
 *   broad : prefixes /0../32, wildcard ports common. Some near-catch-all rules
 *           sit early in the list, so a first match is usually found early.
 *   acl   : specific rules like a real ACL - /24../32 prefixes, exact
 *           protocol and server port - plus the default at the end, so most
 *           lookups have to go deep (or all the way) into the list.
 * Lookups are
 * 50% "near a rule" (likely to match somewhere in the list) and 50% random
 * (usually match nothing and fall through to the default). Both classifiers
 * are checked to return the same rule for every lookup.
 *
 * usage: bench_rules [lookups] [broad|acl]      prints CSV to stdout
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rules.h"

static uint64_t rng = 0x243f6a8885a308d3ull;
static uint32_t rnd(void) {           /* xorshift64*, deterministic across platforms */
    rng ^= rng >> 12; rng ^= rng << 25; rng ^= rng >> 27;
    return (uint32_t)((rng * 0x2545f4914f6cdd1dull) >> 32);
}

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static const uint8_t lens[] = {0, 8, 16, 16, 24, 24, 24, 32};
static const uint16_t ports[] = {0, 0, 0, 0, 53, 80, 443, 443, 22, 25, 123, 3389, 8080, 8443};

static const uint8_t acl_slen[] = {16, 24, 24, 32, 32, 32};
static const uint8_t acl_dlen[] = {24, 32, 32, 32};
static const uint16_t acl_ports[] = {53, 80, 443, 22, 25, 123, 3389, 8080, 8443, 993, 5060, 1194};

static void gen_rules(ruleset_t *rs, int n, int acl) {
    rules_init(rs);
    for (int i = 0; i < n; i++) {
        rule_t r = {0};
        if (acl) {
            r.slen = acl_slen[rnd() % 6];
            r.dlen = acl_dlen[rnd() % 4];
            r.src = 10u << 24 | (rnd() & 0xffffff);
            r.dst = (100u + rnd() % 100) << 24 | (rnd() & 0xffffff);
            r.proto = (uint8_t)(rnd() % 3 ? 6 : 17);
            r.dport = acl_ports[rnd() % 12];
            r.app = rnd() % 10 == 0 ? (uint16_t)(1 + rnd() % 20) : 0;
            r.action = (uint8_t)(rnd() % 2);
            rules_add(rs, &r);
            continue;
        }
        r.slen = lens[rnd() % 8];
        r.dlen = lens[rnd() % 8];
        r.src = 10u << 24 | (rnd() & 0xffffff);
        r.dst = (100u + rnd() % 100) << 24 | (rnd() & 0xffffff);
        r.proto = (uint8_t)(rnd() % 4 == 0 ? 0 : rnd() % 3 ? 6 : 17);
        r.dport = ports[rnd() % 14];
        r.sport = rnd() % 20 == 0 ? (uint16_t)(1024 + rnd() % 64) : 0;
        r.app = rnd() % 5 == 0 ? (uint16_t)(1 + rnd() % 20) : 0;
        r.cat = rnd() % 10 == 0 ? (uint8_t)(1 + rnd() % 6) : 0;
        r.action = (uint8_t)(rnd() % 2);
        rules_add(rs, &r);
    }
    rule_t def = {.action = ACT_ALLOW};                    /* default allow, last */
    rules_add(rs, &def);
    rules_build_tss(rs);
}

int main(int argc, char **argv) {
    int lookups = argc > 1 ? atoi(argv[1]) : 1000000;
    int acl = argc > 2 && argv[2][0] == 'a';
    static const int sizes[] = {10, 100, 300, 1000, 3000, 10000, 30000};
    printf("profile,rules,shapes,linear_ns,tss_ns,speedup,rules_bytes,tss_bytes,lookups,mismatches,default_hits\n");
    rkey_t *keys = malloc((size_t)lookups * sizeof *keys);
    for (size_t si = 0; si < sizeof sizes / sizeof *sizes; si++) {
        ruleset_t rs;
        gen_rules(&rs, sizes[si], acl);
        for (int i = 0; i < lookups; i++) {
            rkey_t k;
            if (rnd() % 2) {                              /* near a rule */
                const rule_t *r = &rs.r[rnd() % rs.n];
                k.src = r->src | (rnd() & ~(r->slen ? 0xffffffffu << (32 - r->slen) : 0u));
                k.dst = r->dst | (rnd() & ~(r->dlen ? 0xffffffffu << (32 - r->dlen) : 0u));
                k.dport = r->dport ? r->dport : ports[rnd() % 14];
                k.sport = r->sport ? r->sport : (uint16_t)(1024 + rnd() % 60000);
            } else {
                k.src = rnd(); k.dst = rnd();
                k.dport = ports[rnd() % 14]; k.sport = (uint16_t)(1024 + rnd() % 60000);
            }
            k.proto = (uint8_t)(rnd() % 3 ? 6 : 17);
            k.app = (uint16_t)(rnd() % 21);
            k.cat = (uint8_t)(rnd() % 7);
            k.v6 = 0;
            keys[i] = k;
        }
        /* verify equivalence first (also warms the caches) */
        long mism = 0, defs = 0;
        for (int i = 0; i < lookups; i++) {
            int a = rules_match_linear(&rs, &keys[i]);
            mism += a != rules_match_tss(&rs, &keys[i]);
            defs += a == (int)rs.n - 1;
        }
        volatile long sink = 0;
        int reps_lin = sizes[si] >= 3000 ? 1 : 3;
        double best_lin = 1e9, best_tss = 1e9;
        for (int rep = 0; rep < reps_lin; rep++) {
            double t0 = now_s();
            int n = sizes[si] >= 10000 ? lookups / 10 : lookups;   /* linear at 10k+ is slow */
            for (int i = 0; i < n; i++) sink += rules_match_linear(&rs, &keys[i]);
            double t = (now_s() - t0) / n;
            if (t < best_lin) best_lin = t;
        }
        for (int rep = 0; rep < 3; rep++) {
            double t0 = now_s();
            for (int i = 0; i < lookups; i++) sink += rules_match_tss(&rs, &keys[i]);
            double t = (now_s() - t0) / lookups;
            if (t < best_tss) best_tss = t;
        }
        size_t tss_bytes = rs.nshapes * sizeof(tss_shape_t);
        for (uint32_t s = 0; s < rs.nshapes; s++) tss_bytes += rs.shapes[s].cap * sizeof(struct tss_ent);
        printf("%s,%u,%u,%.1f,%.1f,%.2f,%zu,%zu,%d,%ld,%ld\n", acl ? "acl" : "broad", rs.n, rs.nshapes, best_lin * 1e9, best_tss * 1e9,
               best_lin / best_tss, rs.n * sizeof(rule_t), tss_bytes, lookups, mism, defs);
        fflush(stdout);
        rules_free(&rs);
        (void)sink;
    }
    free(keys);
    return 0;
}
