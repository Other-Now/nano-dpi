/* reasm.h - tiny byte-range reassembly buffer.
 *
 * Used for the *first client flight only* (TCP bytes for HTTP/TLS, QUIC
 * CRYPTO-frame bytes for the QUIC ClientHello). Bytes are written at their
 * stream offset and a bitmap records which offsets have arrived, so
 * out-of-order segments, retransmissions and overlaps all take the same path.
 * `contig` is the length of the gap-free prefix the parsers may read.
 */
#ifndef NANODPI_REASM_H
#define NANODPI_REASM_H
#include <stdint.h>

#define REASM_CAP 8192

typedef struct {
    uint32_t contig;                 /* bytes [0, contig) are all present */
    uint32_t hi;                     /* highest offset written + 1 */
    uint8_t  data[REASM_CAP];
    uint8_t  have[REASM_CAP / 8];
} reasm_t;

/* Write len bytes at stream offset off. Bytes beyond REASM_CAP are dropped.
 * Returns the new contig length. */
uint32_t reasm_put(reasm_t *r, uint32_t off, const uint8_t *src, uint32_t len);

#endif
