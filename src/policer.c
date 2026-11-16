#include "policer.h"
#include <stdlib.h>
#include <string.h>

#define NS 1000000000ull

void srtcm_init(srtcm_t *m, const srtcm_cfg_t *c) {
    m->tc = c->cbs * NS;
    m->te = c->ebs * NS;
    m->last_ns = 0;
    m->started = 0;
}

int srtcm_color(srtcm_t *m, const srtcm_cfg_t *c, uint64_t now_ns, uint32_t bytes) {
    if (!m->started) { m->started = 1; m->last_ns = now_ns; }
    if (now_ns > m->last_ns && c->cir_Bps) {
        uint64_t dt = now_ns - m->last_ns;
        /* no point adding more than both buckets can hold; also keeps
         * cir*dt far from 64-bit overflow */
        uint64_t full_ns = (c->cbs + c->ebs) * NS / c->cir_Bps + 1;
        if (dt > full_ns) dt = full_ns;
        uint64_t add = c->cir_Bps * dt;
        uint64_t cmax = c->cbs * NS, emax = c->ebs * NS;
        uint64_t room_c = cmax - m->tc;
        if (add <= room_c) m->tc += add;
        else {
            m->tc = cmax;
            add -= room_c;
            m->te = m->te + add > emax ? emax : m->te + add;
        }
        m->last_ns = now_ns;
    }
    uint64_t b = (uint64_t)bytes * NS;
    if (m->tc >= b) { m->tc -= b; return POL_GREEN; }
    if (m->te >= b) { m->te -= b; return POL_YELLOW; }
    return POL_RED;
}

static uint32_t pm_hash(uint16_t pid, const uint8_t a[16]) {
    uint64_t x, y;
    memcpy(&x, a, 8);
    memcpy(&y, a + 8, 8);
    uint64_t h = (x * 0x9e3779b97f4a7c15ull) ^ (y + pid) * 0xc2b2ae3d27d4eb4full;
    return (uint32_t)(h ^ (h >> 31));
}

srtcm_t *polmap_get(polmap_t *pm, uint16_t pid, const uint8_t addr[16], const srtcm_cfg_t *c) {
    if ((pm->n + 1) * 2 > pm->cap) {                       /* grow at 50% load */
        uint32_t ncap = pm->cap ? pm->cap * 2 : 256;
        struct pm_ent *ne = calloc(ncap, sizeof *ne);
        if (!ne) return NULL;
        for (uint32_t i = 0; i < pm->cap; i++) {
            if (!pm->e[i].used) continue;
            uint32_t j = pm_hash(pm->e[i].pid, pm->e[i].addr) & (ncap - 1);
            while (ne[j].used) j = (j + 1) & (ncap - 1);
            ne[j] = pm->e[i];
        }
        free(pm->e);
        pm->e = ne;
        pm->cap = ncap;
    }
    for (uint32_t j = pm_hash(pid, addr) & (pm->cap - 1);; j = (j + 1) & (pm->cap - 1)) {
        struct pm_ent *e = &pm->e[j];
        if (!e->used) {
            e->used = 1;
            e->pid = pid;
            memcpy(e->addr, addr, 16);
            srtcm_init(&e->m, c);
            pm->n++;
            return &e->m;
        }
        if (e->pid == pid && memcmp(e->addr, addr, 16) == 0) return &e->m;
    }
}

void polmap_free(polmap_t *pm) {
    free(pm->e);
    memset(pm, 0, sizeof *pm);
}
