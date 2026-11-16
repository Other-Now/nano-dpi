/* engine.h - the per-packet pipeline.
 *
 *   decode -> flow lookup/create -> TCP state -> DPI (first client flight
 *   only) -> verdict (cached on the flow) -> policer (per subscriber)
 *
 * Firewall rules are evaluated when a flow is created (L3/L4 fields only)
 * and once more when DPI has named the app; every other packet just reads
 * the cached verdict from the flow. That is why per-packet cost hardly
 * depends on the number of rules.
 */
#ifndef NANODPI_ENGINE_H
#define NANODPI_ENGINE_H
#include <stdint.h>
#include "apps.h"
#include "flow.h"
#include "pcapio.h"
#include "policer.h"
#include "rules.h"

#define DPI_MAX_PKTS 10   /* give up on a flow after this many client payload packets */

typedef struct {
    ftab_t     ft;
    apps_t    *apps;       /* may be NULL */
    ruleset_t *rs;         /* may be NULL: allow everything */
    polmap_t   pm;
    int        reasm;      /* 1: reassemble first flight; 0: parse each packet alone */
    int        use_tss;    /* 1: TSS classifier; 0: linear */
    uint64_t   last_sweep_ns;
    uint64_t   sweep_ns;   /* expiry sweep period in trace time, 0 = never */
    uint64_t   first_ts_ns, last_ts_ns;   /* trace time covered */
    flow_cb    on_close;   /* called for every flow when it expires / is reused / at the end */
    void      *ctx;

    struct {
        uint64_t pkts, bytes, not_ip, trunc, frag, other_l4, untracked;
        uint64_t l7[L7_N], with_host;
        uint64_t fw_evals, drop_pkts, drop_bytes;
        uint64_t pol[3], pol_bytes[3];
    } st;
} engine_t;

int  engine_init(engine_t *e, uint32_t flow_cap, apps_t *apps, ruleset_t *rs);
/* returns ACT_ALLOW or ACT_DROP for this packet */
int  engine_packet(engine_t *e, const cap_pkt_t *cp);
void engine_finish(engine_t *e);   /* report all remaining flows via on_close */
void engine_free(engine_t *e);

#endif
