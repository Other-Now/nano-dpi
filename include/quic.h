/* quic.h - read the SNI out of a QUIC client Initial (RFC 9000/9001).
 *
 * Initial packets are encrypted, but with keys anyone can compute:
 *   initial_secret = HKDF-Extract(version_salt, client_DCID)
 *   client_secret  = HKDF-Expand-Label(initial_secret, "client in", 32)
 *   key/iv/hp      = HKDF-Expand-Label(client_secret, "quic key"/"quic iv"/"quic hp")
 * So a middlebox can remove header protection, AES-128-GCM-decrypt the
 * payload, collect CRYPTO frames (which may arrive out of order and across
 * several Initial packets) and parse the TLS ClientHello inside.
 */
#ifndef NANODPI_QUIC_H
#define NANODPI_QUIC_H
#include <stddef.h>
#include <stdint.h>
#include "dpi.h"
#include "reasm.h"

/* Derive client Initial key material. Returns 0 if the version is unknown. */
int quic_client_keys(uint32_t version, const uint8_t *dcid, uint8_t dcid_len,
                     uint8_t key[16], uint8_t iv[12], uint8_t hp[16]);

/* Inspect one client->server UDP datagram.
 * dcid/dcid_len/version are per-flow state: filled from the first Initial
 * (later Initials may carry a server-chosen DCID but keep the first keys).
 * CRYPTO data is written into rb. */
dpi_res_t quic_inspect(const uint8_t *d, uint32_t n,
                       uint8_t dcid[20], uint8_t *dcid_len, uint32_t *version,
                       reasm_t *rb, char *host, size_t hostsz);

extern uint64_t quic_decrypt_ok, quic_decrypt_fail;

#endif
