/* policer.h - single-rate three-colour marker (srTCM, RFC 2697), colour-blind.
 *
 * Two token buckets fed at CIR: C (size CBS) fills first, overflow goes to
 * E (size EBS). A packet of B bytes is GREEN if C >= B, else YELLOW if
 * E >= B, else RED. We pass green+yellow and drop red, so over a long
 * interval T the passed rate is CIR + (CBS+EBS)/T.
 *
 * Tokens are kept in "byte-nanoseconds" (bytes * 1e9) so refill is pure
 * integer maths: tokens += CIR_bytes_per_sec * elapsed_ns.
 */
#ifndef NANODPI_POLICER_H
#define NANODPI_POLICER_H
#include <stdint.h>

enum { POL_GREEN = 0, POL_YELLOW = 1, POL_RED = 2 };

typedef struct {
    uint64_t cir_Bps;     /* committed rate, bytes/s */
    uint64_t cbs, ebs;    /* bucket sizes, bytes */
} srtcm_cfg_t;

typedef struct {
    uint64_t tc, te;      /* tokens, in bytes*1e9 */
    uint64_t last_ns;
    int      started;
} srtcm_t;

void srtcm_init(srtcm_t *m, const srtcm_cfg_t *c);   /* buckets start full */
int  srtcm_color(srtcm_t *m, const srtcm_cfg_t *c, uint64_t now_ns, uint32_t bytes);

/* per-subscriber instances: (policer id, subscriber address) -> srtcm_t */
typedef struct {
    struct pm_ent { uint16_t pid; uint8_t used; uint8_t addr[16]; srtcm_t m; } *e;
    uint32_t cap, n;
} polmap_t;

srtcm_t *polmap_get(polmap_t *pm, uint16_t pid, const uint8_t addr[16], const srtcm_cfg_t *c);
void     polmap_free(polmap_t *pm);

#endif
