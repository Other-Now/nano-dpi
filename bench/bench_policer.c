/* bench_policer - does the srTCM policer pass the rate it was configured for?
 *
 * Simulated time (no wall clock): Poisson arrivals, IMIX packet sizes
 * (64/576/1500 in 7:4:1), offered load = factor x CIR, 30 simulated seconds.
 * Expected passed rate = min(offered, CIR) plus at most (CBS+EBS)/T from the
 * buckets starting full. Prints CSV.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "policer.h"

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static double urand(void) {
    rng ^= rng >> 12; rng ^= rng << 25; rng ^= rng >> 27;
    return ((rng * 0x2545f4914f6cdd1dull) >> 11) * (1.0 / 9007199254740992.0);
}

int main(void) {
    static const double cir_bits[] = {1e6, 10e6, 100e6, 1e9};
    static const double factors[] = {0.5, 0.9, 1.1, 2.0, 10.0};
    static const int sizes[12] = {64, 64, 64, 64, 64, 64, 64, 576, 576, 576, 576, 1500};
    const double T = 30.0;
    printf("cir_mbps,offered_x,offered_mbps,passed_mbps,expected_mbps,error_pct,green_pct,yellow_pct,red_pct,packets\n");
    for (int ci = 0; ci < 4; ci++) {
        for (int fi = 0; fi < 5; fi++) {
            srtcm_cfg_t c;
            c.cir_Bps = (uint64_t)(cir_bits[ci] / 8);
            c.cbs = c.cir_Bps / 100 > 3000 ? c.cir_Bps / 100 : 3000;   /* 10 ms of CIR */
            c.ebs = 2 * c.cbs;
            srtcm_t m;
            srtcm_init(&m, &c);
            double mean_pkt = (7 * 64 + 4 * 576 + 1500) / 12.0;
            double offered_Bps = factors[fi] * c.cir_Bps;
            double pps = offered_Bps / mean_pkt;
            double t = 0;
            uint64_t offered = 0, passed = 0, cnt[3] = {0}, n = 0;
            while (1) {
                t += -log(1.0 - urand()) / pps;
                if (t >= T) break;
                int sz = sizes[(int)(urand() * 12) % 12];
                int col = srtcm_color(&m, &c, (uint64_t)(t * 1e9), (uint32_t)sz);
                cnt[col]++;
                n++;
                offered += (uint64_t)sz;
                if (col != POL_RED) passed += (uint64_t)sz;
            }
            double off_r = offered * 8 / T / 1e6, pass_r = passed * 8 / T / 1e6;
            double cap = (c.cir_Bps * T + c.cbs + c.ebs) * 8 / T / 1e6;
            double expected = off_r < cap ? off_r : cap;
            printf("%.0f,%.1f,%.3f,%.3f,%.3f,%.3f,%.1f,%.1f,%.1f,%lu\n", cir_bits[ci] / 1e6, factors[fi], off_r,
                   pass_r, expected, (pass_r - expected) / expected * 100, 100.0 * cnt[0] / n, 100.0 * cnt[1] / n,
                   100.0 * cnt[2] / n, (unsigned long)n);
        }
    }
    return 0;
}
