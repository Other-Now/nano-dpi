/* libFuzzer target: arbitrary bytes -> a stream of packets through the whole
 * engine (decode, flow table, TCP state, reassembly, HTTP/TLS/DNS/QUIC
 * parsers), plus each parser called directly on the raw input. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dpi.h"
#include "engine.h"
#include "quic.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
    char h[96];
    uint32_t n32 = (uint32_t)(n > 65535 ? 65535 : n);
    dpi_http_host(d, n32, h, sizeof h);
    dpi_tls_sni(d, n32, h, sizeof h);
    dpi_tls_handshake_sni(d, n32, h, sizeof h);
    dpi_dns_qname(d, n32, 0, h, sizeof h);
    dpi_dns_qname(d, n32, 1, h, sizeof h);
    reasm_t *rb = calloc(1, sizeof *rb);
    uint8_t dcid[20], dl = 0;
    uint32_t ver = 0;
    quic_inspect(d, n32, dcid, &dl, &ver, rb, h, sizeof h);
    free(rb);

    /* packets: [linktype selector][len hi][len lo][bytes...] repeated */
    static const int lt[] = {1, 113, 276, 0, 101, 229};
    engine_t e;
    if (engine_init(&e, 64, NULL, NULL)) return 0;
    size_t o = 0;
    uint64_t ts = 0;
    while (o + 3 <= n) {
        int link = lt[d[o] % 6];
        uint32_t len = (uint32_t)d[o + 1] << 8 | d[o + 2];
        o += 3;
        if (len > n - o) len = (uint32_t)(n - o);
        cap_pkt_t cp = {.data = d + o, .caplen = len, .wirelen = len, .ts_ns = ts, .linktype = link};
        engine_packet(&e, &cp);
        ts += 400000000ull * (d[o - 3] >> 4);   /* sometimes jump seconds: exercises expiry */
        o += len;
    }
    engine_finish(&e);
    engine_free(&e);
    return 0;
}
