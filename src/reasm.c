#include "reasm.h"
#include <string.h>

uint32_t reasm_put(reasm_t *r, uint32_t off, const uint8_t *src, uint32_t len) {
    if (off >= REASM_CAP) return r->contig;
    if (len > REASM_CAP - off) len = REASM_CAP - off;
    /* first writer wins for overlapping bytes (same policy as Linux/Windows
     * for most overlaps; a real IPS must pick one and normalise) */
    for (uint32_t i = 0; i < len; i++) {
        uint32_t o = off + i;
        if (!(r->have[o >> 3] & (1u << (o & 7)))) {
            r->data[o] = src[i];
            r->have[o >> 3] |= (uint8_t)(1u << (o & 7));
        }
    }
    if (off + len > r->hi) r->hi = off + len;
    while (r->contig < r->hi && (r->have[r->contig >> 3] & (1u << (r->contig & 7))))
        r->contig++;
    return r->contig;
}
