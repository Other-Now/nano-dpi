#include "rules.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline uint32_t pmask(uint8_t len) { return len ? 0xffffffffu << (32 - len) : 0; }

void rules_init(ruleset_t *rs) { memset(rs, 0, sizeof *rs); }

static void free_shapes(ruleset_t *rs) {
    for (uint32_t i = 0; i < rs->nshapes; i++) free(rs->shapes[i].tab);
    free(rs->shapes);
    rs->shapes = NULL;
    rs->nshapes = 0;
}

void rules_free(ruleset_t *rs) {
    free_shapes(rs);
    free(rs->r);
    for (int i = 0; i < rs->npol; i++) free(rs->pol_name[i]);
    memset(rs, 0, sizeof *rs);
}

int rules_add(ruleset_t *rs, const rule_t *r) {
    if (rs->n == rs->cap) {
        uint32_t nc = rs->cap ? rs->cap * 2 : 64;
        rule_t *nr = realloc(rs->r, nc * sizeof *nr);
        if (!nr) return -1;
        rs->r = nr;
        rs->cap = nc;
    }
    rule_t x = *r;
    x.src &= pmask(x.slen);
    x.dst &= pmask(x.dlen);
    if (x.app || x.cat) rs->uses_l7 = 1;
    rs->r[rs->n++] = x;
    return 0;
}

/* ---------------------------------------------------------------- linear */

static inline int rule_hit(const rule_t *r, const rkey_t *k) {
    if (k->v6 && (r->slen || r->dlen)) return 0;
    return ((k->src & pmask(r->slen)) == r->src) &&
           ((k->dst & pmask(r->dlen)) == r->dst) &&
           (!r->proto || r->proto == k->proto) &&
           (!r->sport || r->sport == k->sport) &&
           (!r->dport || r->dport == k->dport) &&
           (!r->app || r->app == k->app) &&
           (!r->cat || r->cat == k->cat);
}

int rules_match_linear(const ruleset_t *rs, const rkey_t *k) {
    for (uint32_t i = 0; i < rs->n; i++)
        if (rule_hit(&rs->r[i], k)) return (int)i;
    return -1;
}

/* ------------------------------------------------------------------- TSS */

static uint8_t any_mask_of(const rule_t *r) {
    return (uint8_t)((!r->proto) | (!r->sport) << 1 | (!r->dport) << 2 | (!r->app) << 3 | (!r->cat) << 4);
}

/* pack the masked fields of a flow (or rule) for one shape into 128 bits */
static inline void shape_key(const tss_shape_t *s, uint32_t src, uint32_t dst, uint8_t proto,
                             uint16_t sport, uint16_t dport, uint16_t app, uint8_t cat,
                             uint64_t *k0, uint64_t *k1) {
    uint8_t m = s->any_mask;
    *k0 = (uint64_t)(src & pmask(s->slen)) << 32 | (dst & pmask(s->dlen));
    *k1 = (uint64_t)(m & 1 ? 0 : proto) << 56 | (uint64_t)(m & 16 ? 0 : cat) << 48 |
          (uint64_t)(m & 2 ? 0 : sport) << 32 | (uint64_t)(m & 4 ? 0 : dport) << 16 |
          (uint64_t)(m & 8 ? 0 : app);
}

static inline uint32_t hash128(uint64_t a, uint64_t b) {
    uint64_t h = a * 0x9e3779b97f4a7c15ull ^ (b + 0x632be59bd9b4e019ull) * 0xc2b2ae3d27d4eb4full;
    h ^= h >> 29;
    h *= 0xbf58476d1ce4e5b9ull;
    return (uint32_t)(h ^ (h >> 32));
}

static int cmp_shape(const void *a, const void *b) {
    const tss_shape_t *x = a, *y = b;
    return (x->best > y->best) - (x->best < y->best);
}

void rules_build_tss(ruleset_t *rs) {
    free_shapes(rs);
    /* 1. find distinct shapes and count rules per shape */
    uint32_t *cnt = calloc(rs->n + 1, sizeof *cnt);
    rs->shapes = calloc(rs->n + 1, sizeof *rs->shapes);
    for (uint32_t i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->r[i];
        uint8_t am = any_mask_of(r);
        uint32_t s;
        for (s = 0; s < rs->nshapes; s++)
            if (rs->shapes[s].slen == r->slen && rs->shapes[s].dlen == r->dlen && rs->shapes[s].any_mask == am) break;
        if (s == rs->nshapes) {
            rs->shapes[s] = (tss_shape_t){.slen = r->slen, .dlen = r->dlen, .any_mask = am, .best = (int32_t)i};
            rs->nshapes++;
        }
        cnt[s]++;
    }
    /* 2. size each shape's table at <= 50% load and insert rules; for
     *    duplicate keys keep the lowest index (first match wins) */
    for (uint32_t s = 0; s < rs->nshapes; s++) {
        uint32_t c = 4;
        while (c < cnt[s] * 2) c <<= 1;
        rs->shapes[s].cap = c;
        rs->shapes[s].tab = malloc(c * sizeof *rs->shapes[s].tab);
        for (uint32_t j = 0; j < c; j++) rs->shapes[s].tab[j].idx = -1;
    }
    for (uint32_t i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->r[i];
        uint8_t am = any_mask_of(r);
        tss_shape_t *sh = NULL;
        for (uint32_t s = 0; s < rs->nshapes; s++)
            if (rs->shapes[s].slen == r->slen && rs->shapes[s].dlen == r->dlen && rs->shapes[s].any_mask == am) { sh = &rs->shapes[s]; break; }
        uint64_t k0, k1;
        shape_key(sh, r->src, r->dst, r->proto, r->sport, r->dport, r->app, r->cat, &k0, &k1);
        for (uint32_t j = hash128(k0, k1) & (sh->cap - 1);; j = (j + 1) & (sh->cap - 1)) {
            struct tss_ent *e = &sh->tab[j];
            if (e->idx < 0) { e->k0 = k0; e->k1 = k1; e->idx = (int32_t)i; break; }
            if (e->k0 == k0 && e->k1 == k1) break;      /* earlier rule already owns this key */
        }
    }
    free(cnt);
    /* 3. visit shapes in priority order so lookups can stop early */
    qsort(rs->shapes, rs->nshapes, sizeof *rs->shapes, cmp_shape);
}

int rules_match_tss(const ruleset_t *rs, const rkey_t *k) {
    int best = -1;
    for (uint32_t s = 0; s < rs->nshapes; s++) {
        const tss_shape_t *sh = &rs->shapes[s];
        if (best >= 0 && sh->best > best) break;        /* nothing left can win */
        if (k->v6 && (sh->slen || sh->dlen)) continue;
        uint64_t k0, k1;
        shape_key(sh, k->src, k->dst, k->proto, k->sport, k->dport, k->app, k->cat, &k0, &k1);
        for (uint32_t j = hash128(k0, k1) & (sh->cap - 1);; j = (j + 1) & (sh->cap - 1)) {
            const struct tss_ent *e = &sh->tab[j];
            if (e->idx < 0) break;
            if (e->k0 == k0 && e->k1 == k1) {
                if (best < 0 || e->idx < best) best = e->idx;
                break;
            }
        }
    }
    return best;
}

/* --------------------------------------------------------------- parsing */

static uint64_t parse_size(const char *s, int bits) {
    char *e;
    double v = strtod(s, &e);
    switch (*e) {
    case 'k': case 'K': v *= 1e3; break;
    case 'm': case 'M': v *= 1e6; break;
    case 'g': case 'G': v *= 1e9; break;
    default: break;
    }
    return (uint64_t)(bits ? v / 8 : v);
}

static int parse_cidr(const char *s, uint32_t *addr, uint8_t *len) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", s);
    char *slash = strchr(buf, '/');
    int l = 32;
    if (slash) { *slash = 0; l = atoi(slash + 1); }
    struct in_addr a;
    if (l < 0 || l > 32 || inet_pton(AF_INET, buf, &a) != 1) return -1;
    *addr = ntohl(a.s_addr);
    *len = (uint8_t)l;
    return 0;
}

int rules_parse_line(ruleset_t *rs, const apps_t *apps, const char *line) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s", line);
    char *save = NULL, *tok = strtok_r(buf, " \t\r\n", &save);
    if (!tok || tok[0] == '#') return 1;

    if (strcmp(tok, "policer") == 0) {
        if (rs->npol >= MAX_POLICERS) return -1;
        char *name = strtok_r(NULL, " \t\r\n", &save);
        if (!name) return -1;
        srtcm_cfg_t c = {0};
        while ((tok = strtok_r(NULL, " \t\r\n", &save))) {
            if (!strncmp(tok, "cir=", 4)) c.cir_Bps = parse_size(tok + 4, 1);   /* bits/s */
            else if (!strncmp(tok, "cbs=", 4)) c.cbs = parse_size(tok + 4, 0);  /* bytes */
            else if (!strncmp(tok, "ebs=", 4)) c.ebs = parse_size(tok + 4, 0);
            else return -1;
        }
        if (!c.cir_Bps || !c.cbs) return -1;
        rs->pol[rs->npol] = c;
        rs->pol_name[rs->npol++] = strdup(name);
        return 0;
    }

    rule_t r = {0};
    if (strcmp(tok, "allow") == 0) r.action = ACT_ALLOW;
    else if (strcmp(tok, "drop") == 0) r.action = ACT_DROP;
    else if (strncmp(tok, "police=", 7) == 0) {
        r.action = ACT_POLICE;
        for (int i = 0; i < rs->npol; i++)
            if (strcmp(rs->pol_name[i], tok + 7) == 0) r.policer = (uint16_t)(i + 1);
        if (!r.policer) { fprintf(stderr, "unknown policer %s\n", tok + 7); return -1; }
    } else return -1;

    while ((tok = strtok_r(NULL, " \t\r\n", &save))) {
        if (!strncmp(tok, "src=", 4)) { if (parse_cidr(tok + 4, &r.src, &r.slen)) return -1; }
        else if (!strncmp(tok, "dst=", 4)) { if (parse_cidr(tok + 4, &r.dst, &r.dlen)) return -1; }
        else if (!strncmp(tok, "proto=", 6)) {
            const char *p = tok + 6;
            r.proto = (uint8_t)(!strcmp(p, "tcp") ? 6 : !strcmp(p, "udp") ? 17 : atoi(p));
        }
        else if (!strncmp(tok, "sport=", 6)) r.sport = (uint16_t)atoi(tok + 6);
        else if (!strncmp(tok, "dport=", 6)) r.dport = (uint16_t)atoi(tok + 6);
        else if (!strncmp(tok, "app=", 4)) {
            r.app = (uint16_t)apps_app_id(tok + 4);
            if (!r.app) { fprintf(stderr, "unknown app %s\n", tok + 4); return -1; }
        }
        else if (!strncmp(tok, "cat=", 4)) {
            r.cat = (uint8_t)apps_cat_id(apps, tok + 4);
            if (!r.cat) { fprintf(stderr, "unknown category %s\n", tok + 4); return -1; }
        }
        else return -1;
    }
    return rules_add(rs, &r);
}

int rules_load(ruleset_t *rs, const apps_t *apps, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    char line[512];
    int ln = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (rules_parse_line(rs, apps, line) < 0) {
            fprintf(stderr, "%s:%d: bad rule: %s", path, ln, line);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    rules_build_tss(rs);
    return 0;
}
