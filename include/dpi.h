/* dpi.h - application identification from the first client bytes.
 *
 * Every parser reads "as far as the bytes go": given a prefix of the stream
 * it either identifies the protocol (DPI_MATCH, host filled in or ""),
 * rules it out (DPI_NO), or asks for more bytes (DPI_NEED_MORE).
 * That contract is what makes TCP reassembly matter: a ClientHello whose SNI
 * extension sits in the second segment returns NEED_MORE on segment one.
 */
#ifndef NANODPI_DPI_H
#define NANODPI_DPI_H
#include <stddef.h>
#include <stdint.h>

typedef enum { DPI_NO = 0, DPI_NEED_MORE, DPI_MATCH } dpi_res_t;

dpi_res_t dpi_http_host(const uint8_t *d, uint32_t n, char *host, size_t hostsz);
/* TLS record stream (TCP) */
dpi_res_t dpi_tls_sni(const uint8_t *d, uint32_t n, char *host, size_t hostsz);
/* bare handshake messages (QUIC CRYPTO stream) */
dpi_res_t dpi_tls_handshake_sni(const uint8_t *hs, uint32_t n, char *host, size_t hostsz);
/* DNS message; tcp=1 means a 2-byte length prefix precedes it */
dpi_res_t dpi_dns_qname(const uint8_t *d, uint32_t n, int tcp, char *host, size_t hostsz);

#endif
