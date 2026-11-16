/* rules.h - first-match firewall rules, two classifiers with identical results.
 *
 * A rule matches on: client IPv4 prefix, server IPv4 prefix, L4 protocol,
 * client port, server port, application, content category. Each field is
 * either exact (prefix for addresses) or "any". Lower index = higher priority.
 *
 *   linear : test every rule in order, stop at the first match.  O(rules)
 *   tss    : tuple-space search (Srinivasan et al., SIGCOMM'99). Rules that
 *            share the same *shape* (prefix lengths + which fields are "any")
 *            go into one hash table keyed by the masked fields; a lookup does
 *            one hash probe per shape. O(shapes), and shapes << rules.
 *            Shapes are visited in order of their best rule, so the search
 *            stops once no remaining shape can beat the current match.
 *
 * Port ranges are not supported (TSS would need range->prefix expansion).
 */
#ifndef NANODPI_RULES_H
#define NANODPI_RULES_H
#include <stdint.h>
#include "apps.h"
#include "policer.h"

enum { ACT_ALLOW = 0, ACT_DROP = 1, ACT_POLICE = 2 };

typedef struct {
    uint32_t src, dst;      /* IPv4, host byte order, already masked */
    uint8_t  slen, dlen;    /* prefix lengths, 0 = any */
    uint8_t  proto;         /* 0 = any */
    uint8_t  cat;           /* 0 = any */
    uint16_t sport, dport;  /* 0 = any */
    uint16_t app;           /* 0 = any */
    uint8_t  action;
    uint16_t policer;       /* policer index + 1 when action == ACT_POLICE */
} rule_t;

/* what a flow looks like to the classifier */
typedef struct {
    uint32_t src, dst;      /* client / server IPv4 (0 for IPv6) */
    uint8_t  v6;            /* IPv6 flows only match rules with no address */
    uint8_t  proto, cat;
    uint16_t sport, dport, app;
} rkey_t;

typedef struct {            /* one TSS shape */
    uint8_t  slen, dlen;
    uint8_t  any_mask;      /* bit0 proto, 1 sport, 2 dport, 3 app, 4 cat */
    int32_t  best;          /* lowest rule index in this shape */
    uint32_t cap;           /* hash slots (power of two) */
    struct tss_ent { uint64_t k0, k1; int32_t idx; } *tab;
} tss_shape_t;

#define MAX_POLICERS 64

typedef struct {
    rule_t     *r;
    uint32_t    n, cap;
    tss_shape_t *shapes;
    uint32_t    nshapes;
    int         uses_l7;    /* any rule matches on app/cat -> re-classify after DPI */
    srtcm_cfg_t pol[MAX_POLICERS];
    char       *pol_name[MAX_POLICERS];
    int         npol;
} ruleset_t;

void rules_init(ruleset_t *rs);
void rules_free(ruleset_t *rs);
int  rules_add(ruleset_t *rs, const rule_t *r);
/* Parse one line: "policer NAME cir=10m cbs=64k ebs=128k" or
 * "<allow|drop|police=NAME> [src=A/n] [dst=A/n] [proto=tcp|udp|N] [sport=N]
 *  [dport=N] [app=NAME] [cat=NAME]". Returns 0 ok, 1 blank/comment, -1 error. */
int  rules_parse_line(ruleset_t *rs, const apps_t *apps, const char *line);
int  rules_load(ruleset_t *rs, const apps_t *apps, const char *path);
void rules_build_tss(ruleset_t *rs);   /* call after the last rules_add */
int  rules_match_linear(const ruleset_t *rs, const rkey_t *k);   /* index or -1 */
int  rules_match_tss(const ruleset_t *rs, const rkey_t *k);

#endif
