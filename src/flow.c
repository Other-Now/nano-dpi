#include "flow.h"
#include <stdlib.h>
#include <string.h>

const char *const tcp_state_name[TCP_NSTATES] = {
    "NONE", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
    "FIN_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE"};
const char *const l7_name[L7_N] = {"unknown", "HTTP", "TLS", "DNS", "QUIC"};

int ftab_init(ftab_t *t, uint32_t cap_pow2) {
    memset(t, 0, sizeof *t);
    uint32_t cap = 1;
    while (cap < cap_pow2) cap <<= 1;
    t->slots = calloc(cap, sizeof(flow_t));
    t->deadline = calloc(cap, sizeof(uint32_t));
    if (!t->slots || !t->deadline) { free(t->slots); free(t->deadline); return -1; }
    t->cap = cap;
    t->mask = cap - 1;
    t->max_n = cap / 10 * 9;          /* keep probe chains short: refuse past 90% */
    /* Idle timeouts in seconds. Linux conntrack uses 5 days for ESTABLISHED;
     * an inline DPI box can't afford that, so 300 s here. */
    t->timeout_s[TCP_NONE] = 30;
    t->timeout_s[TCP_SYN_SENT] = 30;
    t->timeout_s[TCP_SYN_RCVD] = 30;
    t->timeout_s[TCP_ESTABLISHED] = 300;
    t->timeout_s[TCP_FIN_WAIT] = 120;
    t->timeout_s[TCP_LAST_ACK] = 30;
    t->timeout_s[TCP_TIME_WAIT] = 120;
    t->timeout_s[TCP_CLOSE] = 10;
    t->udp_timeout_s = 30;
    return 0;
}

void ftab_free(ftab_t *t) {
    for (uint32_t i = 0; i < t->cap; i++) free(t->slots[i].rb);
    free(t->slots);
    free(t->deadline);
    t->slots = NULL;
    t->deadline = NULL;
}

void flow_key_from_pkt(const pkt_t *p, flow_key_t *k, int *from_a) {
    int alen = p->ipver == 4 ? 4 : 16;
    int c = memcmp(p->src, p->dst, (size_t)alen);
    int src_low = c < 0 || (c == 0 && p->sport <= p->dport);
    memset(k, 0, sizeof *k);
    k->ipver = p->ipver;
    k->proto = p->proto;
    if (src_low) {
        memcpy(k->a, p->src, 16); memcpy(k->b, p->dst, 16);
        k->ap = p->sport; k->bp = p->dport;
    } else {
        memcpy(k->a, p->dst, 16); memcpy(k->b, p->src, 16);
        k->ap = p->dport; k->bp = p->sport;
    }
    *from_a = src_low;
}

uint32_t flow_hash(const flow_key_t *k) {
    /* 64-bit multiply-xorshift over the 40-byte key */
    const uint8_t *p = (const uint8_t *)k;
    uint64_t h = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i + 8 <= sizeof *k; i += 8) {
        uint64_t w; memcpy(&w, p + i, 8);
        h ^= w;
        h *= 0xff51afd7ed558ccdull;
        h ^= h >> 32;
    }
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 29;
    return (uint32_t)h;
}

static int key_eq(const flow_key_t *x, const flow_key_t *y) {
    return memcmp(x, y, sizeof *x) == 0;
}

/* decide who the client is from the first packet we see */
static int guess_client_is_a(const pkt_t *p, int from_a) {
    int sender_is_client = 1;
    if (p->proto == 6) {
        uint8_t f = p->tcp_flags;
        if ((f & TH_SYN) && !(f & TH_ACK)) sender_is_client = 1;
        else if ((f & TH_SYN) && (f & TH_ACK)) sender_is_client = 0;
        else sender_is_client = !(p->sport < 1024 && p->dport >= 1024);
    } else {
        sender_is_client = !(p->sport < 1024 && p->dport >= 1024);
    }
    return sender_is_client ? from_a : !from_a;
}

flow_t *ftab_get(ftab_t *t, const pkt_t *p, int *dir, int *created) {
    flow_key_t k;
    int from_a;
    flow_key_from_pkt(p, &k, &from_a);
    uint32_t h = flow_hash(&k);
    *created = 0;
    for (uint32_t i = h & t->mask;; i = (i + 1) & t->mask) {
        flow_t *f = &t->slots[i];
        if (!f->used) {
            if (t->n >= t->max_n) { t->full_drops++; return NULL; }
            memset(f, 0, sizeof *f);
            f->k = k;
            f->hash = h;
            f->used = 1;
            f->client_is_a = (uint8_t)guess_client_is_a(p, from_a);
            f->first_ns = f->last_ns = p->ts_ns;
            f->rule = -1;
            ftab_touch(t, f);
            if (++t->n > t->peak) t->peak = t->n;
            t->created++;
            *created = 1;
            *dir = from_a == f->client_is_a ? 0 : 1;
            return f;
        }
        if (f->hash == h && key_eq(&f->k, &k)) {
            *dir = from_a == f->client_is_a ? 0 : 1;
            return f;
        }
    }
}

/* backward-shift delete: pull later members of the probe chain back so
 * lookups never need tombstones */
static void remove_at(ftab_t *t, uint32_t i) {
    free(t->slots[i].rb);
    t->slots[i].rb = NULL;
    uint32_t j = i;
    for (;;) {
        j = (j + 1) & t->mask;
        flow_t *fj = &t->slots[j];
        if (!fj->used) break;
        uint32_t home = fj->hash & t->mask;
        /* can fj move to i? only if its home is not cyclically in (i, j] */
        int in_range = i <= j ? (home > i && home <= j) : (home > i || home <= j);
        if (!in_range) {
            t->slots[i] = *fj;
            t->deadline[i] = t->deadline[j];
            i = j;
        }
    }
    t->deadline[i] = 0;
    t->slots[i].used = 0;
    t->slots[i].rb = NULL;
    t->n--;
}

void ftab_touch(ftab_t *t, const flow_t *f) {
    uint32_t to = f->k.proto == 6 ? t->timeout_s[f->state] : t->udp_timeout_s;
    t->deadline[f - t->slots] = (uint32_t)(f->last_ns / 1000000000ull) + to + 1;  /* +1: never 0 */
}

uint32_t ftab_expire(ftab_t *t, uint64_t now_ns, flow_cb cb, void *ctx) {
    uint32_t n = 0, now_s = (uint32_t)(now_ns / 1000000000ull);
    const uint32_t *dl = t->deadline;
    for (uint32_t i = 0; i < t->cap; i++) {
        for (;;) {   /* re-check slot i after a delete: something may have shifted in */
            if (!dl[i] || dl[i] > now_s) break;      /* empty or not due: struct never touched */
            flow_t *f = &t->slots[i];
            if (cb) cb(f, ctx);
            remove_at(t, i);
            t->expired++;
            n++;
        }
    }
    return n;
}

void ftab_foreach(ftab_t *t, flow_cb cb, void *ctx) {
    for (uint32_t i = 0; i < t->cap; i++)
        if (t->slots[i].used) cb(&t->slots[i], ctx);
}

void flow_reset(flow_t *f) {
    free(f->rb);
    flow_key_t k = f->k;
    uint32_t h = f->hash;
    memset(f, 0, sizeof *f);
    f->k = k;
    f->hash = h;
    f->used = 1;
    f->rule = -1;
}

/* ---------------- TCP state machine (RFC 9293 states, conntrack-style
 * "observer" view: we see both directions and never send anything) ------- */

int tcp_is_reopen(const flow_t *f, int dir, uint8_t flags) {
    (void)dir;
    return (flags & TH_SYN) && !(flags & TH_ACK) &&
           (f->state == TCP_TIME_WAIT || f->state == TCP_CLOSE);
}

void tcp_track(flow_t *f, int dir, uint8_t fl) {
    int syn = fl & TH_SYN, ack = fl & TH_ACK, fin = fl & TH_FIN, rst = fl & TH_RST;
    if (rst) { f->state = TCP_CLOSE; return; }
    switch ((tcp_state_t)f->state) {
    case TCP_NONE:                          /* first packet of the flow */
        if (syn && !ack) f->state = TCP_SYN_SENT;
        else if (syn && ack) f->state = TCP_SYN_RCVD;    /* missed the SYN */
        else { f->state = TCP_ESTABLISHED; f->midstream = 1; }
        if (fin && f->state == TCP_ESTABLISHED) { f->state = TCP_FIN_WAIT; f->first_fin_dir = (uint8_t)(dir + 1); }
        break;
    case TCP_SYN_SENT:
        if (dir == 1 && syn) f->state = TCP_SYN_RCVD;    /* SYN/ACK (or simultaneous open) */
        break;
    case TCP_SYN_RCVD:
        if (dir == 0 && ack && !syn) f->state = TCP_ESTABLISHED;
        if (fin && f->state == TCP_ESTABLISHED) { f->state = TCP_FIN_WAIT; f->first_fin_dir = (uint8_t)(dir + 1); }
        break;
    case TCP_ESTABLISHED:
        if (fin) { f->state = TCP_FIN_WAIT; f->first_fin_dir = (uint8_t)(dir + 1); }
        break;
    case TCP_FIN_WAIT:
        if (fin && dir + 1 != f->first_fin_dir) f->state = TCP_LAST_ACK;
        break;
    case TCP_LAST_ACK:
        /* the final ACK comes from the side that closed first */
        if (ack && !fin && dir + 1 == f->first_fin_dir) f->state = TCP_TIME_WAIT;
        break;
    case TCP_TIME_WAIT:
    case TCP_CLOSE:
    case TCP_NSTATES:
        break;
    }
}
