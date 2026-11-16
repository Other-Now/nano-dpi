/* flow.h - bidirectional flow table + TCP connection state machine.
 *
 * Table: open addressing, linear probing, backward-shift deletion (no
 * tombstones). Both directions of a connection hash to the same slot because
 * the key is canonicalised: the lower (addr, port) endpoint is always `a`.
 */
#ifndef NANODPI_FLOW_H
#define NANODPI_FLOW_H
#include <stdint.h>
#include "pkt.h"
#include "reasm.h"

typedef enum {
    TCP_NONE = 0,     /* non-TCP flows stay here */
    TCP_SYN_SENT,     /* client SYN seen */
    TCP_SYN_RCVD,     /* server SYN/ACK seen */
    TCP_ESTABLISHED,  /* handshake done, or picked up mid-stream */
    TCP_FIN_WAIT,     /* one side sent FIN */
    TCP_LAST_ACK,     /* both sides sent FIN, waiting for the final ACK */
    TCP_TIME_WAIT,    /* final ACK seen */
    TCP_CLOSE,        /* RST seen */
    TCP_NSTATES
} tcp_state_t;

extern const char *const tcp_state_name[TCP_NSTATES];

typedef enum { L7_UNKNOWN = 0, L7_HTTP, L7_TLS, L7_DNS, L7_QUIC, L7_N } l7_t;
extern const char *const l7_name[L7_N];

typedef struct {
    uint8_t  ipver, proto;
    uint16_t ap, bp;            /* ports of endpoint a and b */
    uint8_t  a[16], b[16];      /* canonical: (a,ap) <= (b,bp) */
    uint16_t pad_;              /* 40 bytes total so the hash reads whole words */
} flow_key_t;

typedef struct flow {
    flow_key_t k;
    uint32_t hash;
    uint8_t  used;
    uint8_t  client_is_a;       /* which endpoint opened the connection */
    uint8_t  state;             /* tcp_state_t */
    uint8_t  first_fin_dir;     /* 1 + direction of first FIN, 0 = none */
    uint8_t  midstream;         /* TCP picked up without seeing the SYN */
    uint64_t first_ns, last_ns;
    uint32_t pkts[2];           /* [0] client->server, [1] server->client */
    uint64_t bytes[2];

    /* DPI */
    uint8_t  l7;                /* l7_t */
    uint8_t  dpi_done;
    uint8_t  dpi_pkts;          /* client packets inspected so far */
    uint8_t  cat;               /* category id (apps.h) */
    uint16_t app;               /* app id (apps.h) */
    char     host[96];          /* HTTP Host / TLS SNI / DNS qname / QUIC SNI */
    uint32_t isn;               /* client stream base sequence number */
    uint8_t  isn_valid;
    uint8_t  qdcid_len;         /* QUIC: client's original DCID (keys derive from it) */
    uint8_t  qdcid[20];
    uint32_t qversion;
    reasm_t *rb;                /* first-flight reassembly, freed when DPI is done */

    /* firewall */
    uint8_t  verdict;           /* rules.h action */
    int32_t  rule;              /* index of the matching rule, -1 = default */
    uint16_t policer;           /* policer id + 1, 0 = none */
} flow_t;

typedef struct {
    flow_t  *slots;
    /* Hot/cold split: deadline[i] = trace second at which slot i's flow
     * expires (0 = empty slot). The expiry sweep reads only this 4-byte
     * array instead of touching every 256-byte flow struct. */
    uint32_t *deadline;
    uint32_t cap, mask, n, max_n;
    uint32_t timeout_s[TCP_NSTATES];
    uint32_t udp_timeout_s;
    /* counters */
    uint64_t created, expired, full_drops, reopened;
    uint32_t peak;              /* most flows alive at once */
} ftab_t;

int      ftab_init(ftab_t *t, uint32_t cap_pow2);
void     ftab_free(ftab_t *t);
void     flow_key_from_pkt(const pkt_t *p, flow_key_t *k, int *from_a);
uint32_t flow_hash(const flow_key_t *k);
/* Find the flow; create it if absent. *dir: 0 client->server, 1 reverse.
 * Returns NULL if the table is full (packet is counted in full_drops). */
flow_t  *ftab_get(ftab_t *t, const pkt_t *p, int *dir, int *created);
/* Remove flows idle longer than their state's timeout; cb sees each one
 * before it is cleared. Returns number expired. */
typedef void (*flow_cb)(flow_t *f, void *ctx);
uint32_t ftab_expire(ftab_t *t, uint64_t now_ns, flow_cb cb, void *ctx);
void     ftab_foreach(ftab_t *t, flow_cb cb, void *ctx);
void     flow_reset(flow_t *f);
/* refresh the flow's expiry deadline after last_ns/state changed */
void     ftab_touch(ftab_t *t, const flow_t *f);     /* drop per-connection state, keep the key */

/* TCP state machine. dir as above. Returns 1 if this packet opens a NEW
 * connection on a flow that was closed (SYN after TIME_WAIT/CLOSE: port
 * reuse) - the caller should emit the old record and reset the flow. */
int      tcp_is_reopen(const flow_t *f, int dir, uint8_t flags);
void     tcp_track(flow_t *f, int dir, uint8_t flags);

#endif
