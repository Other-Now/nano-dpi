/* pcapio.h - minimal pcap / pcapng reader (no libpcap dependency).
 *
 * The whole file is read into memory once; cap_next() then hands out
 * pointers into that buffer, so the packet loop does no I/O and no copies.
 */
#ifndef NANODPI_PCAPIO_H
#define NANODPI_PCAPIO_H
#include <stddef.h>
#include <stdint.h>

#define CAP_MAX_IF 256

typedef struct {
    uint8_t *buf;          /* whole file */
    size_t len, off;
    int is_ng;             /* 0 = classic pcap, 1 = pcapng */
    int swap;              /* file byte order != host byte order */
    /* classic pcap */
    int linktype;
    int nsec;              /* timestamps in ns (magic a1b23c4d) */
    /* pcapng: per-interface link type and timestamp resolution */
    int n_if;
    int if_link[CAP_MAX_IF];
    uint64_t if_tsdiv[CAP_MAX_IF]; /* ticks per second */
    uint64_t skipped;      /* packets we could not attribute to an interface */
} cap_t;

typedef struct {
    const uint8_t *data;
    uint32_t caplen, wirelen;
    uint64_t ts_ns;
    int linktype;
} cap_pkt_t;

/* returns 0 on success, -1 on error (message printed to stderr) */
int  cap_open(cap_t *c, const char *path);
/* returns 1 = got packet, 0 = end of file, -1 = malformed file */
int  cap_next(cap_t *c, cap_pkt_t *p);
void cap_close(cap_t *c);

#endif
