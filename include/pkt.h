/* pkt.h - L2..L4 decode into a flat struct. Never reads past caplen. */
#ifndef NANODPI_PKT_H
#define NANODPI_PKT_H
#include <stdint.h>

/* TCP flag bits */
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10

typedef enum {
    PKT_OK = 0,
    PKT_NOT_IP,       /* ARP, LLDP, unknown link type ... */
    PKT_TRUNC,        /* header cut short by snaplen */
    PKT_FRAG,         /* IP fragment (non-first, or first with no L4 we can use) */
    PKT_OTHER_L4,     /* ICMP, GRE, ESP ... (still has addresses) */
} pkt_status_t;

typedef struct {
    uint8_t  ipver;          /* 4 or 6 */
    uint8_t  proto;          /* 6 TCP, 17 UDP, else other */
    uint8_t  src[16], dst[16]; /* IPv4 uses the first 4 bytes, rest zero */
    uint16_t sport, dport;   /* host byte order */
    uint8_t  tcp_flags;
    uint32_t seq, ack;
    const uint8_t *payload;  /* L4 payload (captured part only) */
    uint32_t paylen;         /* captured payload bytes */
    uint32_t wirelen;
    uint64_t ts_ns;
} pkt_t;

pkt_status_t pkt_parse(const uint8_t *d, uint32_t caplen, uint32_t wirelen,
                       int linktype, uint64_t ts_ns, pkt_t *p);

#endif
