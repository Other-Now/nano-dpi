#include "quic.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

uint64_t quic_decrypt_ok, quic_decrypt_fail;

#define V1  0x00000001u
#define V2  0x6b3343cfu

static const uint8_t salt_v1[20] = {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
                                    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
static const uint8_t salt_v2[20] = {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
                                    0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
static const uint8_t salt_d29[20] = {0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,
                                     0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99};
static const uint8_t salt_d23[20] = {0xc3,0xee,0xf7,0x12,0xc7,0x2e,0xbb,0x5a,0x11,0xa7,
                                     0xd2,0x43,0x2b,0xb4,0x63,0x65,0xbe,0xf9,0xf5,0x02};
static const uint8_t salt_d22[20] = {0x7f,0xbc,0xdb,0x0e,0x7c,0x66,0xbb,0xe9,0x19,0x3a,
                                     0x96,0xcd,0x21,0x51,0x9e,0xbd,0x7a,0x02,0x64,0x4a};

static const uint8_t *version_salt(uint32_t v) {
    if (v == V1) return salt_v1;
    if (v == V2) return salt_v2;
    if (v >= 0xff00001du && v <= 0xff000022u) return salt_d29;  /* draft-29..34 */
    if (v >= 0xff000017u && v <= 0xff00001cu) return salt_d23;  /* draft-23..28 */
    if (v == 0xff000016u) return salt_d22;
    if (v == 0xfaceb001u) return salt_d22;                      /* mvfst draft-22 */
    if (v == 0xfaceb002u || v == 0xfaceb00eu) return salt_d23;  /* mvfst draft-27 / exp */
    return NULL;
}

static void hmac_sha256(const uint8_t *k, int kl, const uint8_t *d, int dl, uint8_t out[32]) {
    unsigned int ol = 32;
    HMAC(EVP_sha256(), k, kl, d, (size_t)dl, out, &ol);
}

/* HKDF-Expand-Label (RFC 8446 7.1) with empty context; outlen <= 32 */
static void expand_label(const uint8_t secret[32], const char *label, uint8_t *out, int outlen) {
    uint8_t info[64], t[32];
    int ll = 6 + (int)strlen(label), i = 0;
    info[i++] = 0;
    info[i++] = (uint8_t)outlen;
    info[i++] = (uint8_t)ll;
    memcpy(info + i, "tls13 ", 6); i += 6;
    memcpy(info + i, label, strlen(label)); i += (int)strlen(label);
    info[i++] = 0;                         /* context length */
    info[i++] = 1;                         /* HKDF-Expand counter T(1) */
    hmac_sha256(secret, 32, info, i, t);
    memcpy(out, t, (size_t)outlen);
}

int quic_client_keys(uint32_t version, const uint8_t *dcid, uint8_t dcid_len,
                     uint8_t key[16], uint8_t iv[12], uint8_t hp[16]) {
    const uint8_t *salt = version_salt(version);
    if (!salt) return 0;
    uint8_t initial[32], client[32];
    hmac_sha256(salt, 20, dcid, dcid_len, initial);           /* HKDF-Extract */
    expand_label(initial, "client in", client, 32);
    int v2 = version == V2;
    expand_label(client, v2 ? "quicv2 key" : "quic key", key, 16);
    expand_label(client, v2 ? "quicv2 iv" : "quic iv", iv, 12);
    expand_label(client, v2 ? "quicv2 hp" : "quic hp", hp, 16);
    return 1;
}

/* QUIC variable-length integer; returns bytes consumed, 0 if truncated */
static int varint(const uint8_t *p, uint32_t n, uint64_t *v) {
    if (n < 1) return 0;
    int len = 1 << (p[0] >> 6);
    if ((uint32_t)len > n) return 0;
    uint64_t x = p[0] & 0x3f;
    for (int i = 1; i < len; i++) x = (x << 8) | p[i];
    *v = x;
    return len;
}

static int aes_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int ol = 0, ok = c && EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, key, NULL) &&
                     EVP_CIPHER_CTX_set_padding(c, 0) &&
                     EVP_EncryptUpdate(c, out, &ol, in, 16);
    EVP_CIPHER_CTX_free(c);
    return ok && ol == 16;
}

static int aes_gcm_open(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *aad, int aadl, const uint8_t *ct, int ctl,
                        const uint8_t tag[16], uint8_t *pt) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok = c &&
        EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
        EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) &&
        EVP_DecryptUpdate(c, NULL, &l, aad, aadl) &&
        EVP_DecryptUpdate(c, pt, &l, ct, ctl) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) &&
        EVP_DecryptFinal_ex(c, pt + l, &l) > 0;        /* tag check */
    EVP_CIPHER_CTX_free(c);
    return ok;
}

dpi_res_t quic_inspect(const uint8_t *d, uint32_t n,
                       uint8_t dcid[20], uint8_t *dcid_len, uint32_t *version,
                       reasm_t *rb, char *host, size_t hostsz) {
    host[0] = 0;
    if (n < 7 || !(d[0] & 0x80) || !(d[0] & 0x40)) return DPI_NO;  /* long header, fixed bit */
    uint32_t ver = (uint32_t)d[1] << 24 | (uint32_t)d[2] << 16 | (uint32_t)d[3] << 8 | d[4];
    if (!version_salt(ver)) return DPI_NO;
    int ptype = (d[0] >> 4) & 3;
    if (ptype != (ver == V2 ? 1 : 0)) return DPI_NO;              /* Initial only */

    uint32_t o = 5;
    uint8_t dl = d[o++];
    if (dl > 20 || o + dl + 1 > n) return DPI_NO;
    const uint8_t *pkt_dcid = d + o;
    o += dl;
    uint8_t sl = d[o++];
    if (sl > 20 || o + sl > n) return DPI_NO;
    o += sl;
    uint64_t tok, plen;
    int k = varint(d + o, n - o, &tok);
    if (!k || tok > n) return DPI_NO;
    o += (uint32_t)k + (uint32_t)tok;
    if (o > n) return DPI_NO;
    k = varint(d + o, n - o, &plen);
    if (!k) return DPI_NO;
    o += (uint32_t)k;
    uint32_t pn_off = o;
    if (plen < 20 || plen > n - pn_off) return DPI_NO;

    if (*dcid_len == 0) {                       /* first Initial of the flow fixes the keys */
        if (dl < 8) return DPI_NO;              /* RFC 9000 7.2: client DCID >= 8 bytes */
        memcpy(dcid, pkt_dcid, dl);
        *dcid_len = dl;
        *version = ver;
    }
    uint8_t key[16], iv[12], hp[16], mask[16];
    if (!quic_client_keys(*version, dcid, *dcid_len, key, iv, hp)) return DPI_NO;

    /* remove header protection: sample starts 4 bytes after pn_offset */
    if (!aes_ecb(hp, d + pn_off + 4, mask)) return DPI_NO;
    uint8_t hdr[64 + 1500];
    if (pn_off + 4 > sizeof hdr) return DPI_NO;
    memcpy(hdr, d, pn_off + 4);
    hdr[0] ^= mask[0] & 0x0f;
    uint32_t pn_len = (hdr[0] & 3) + 1, pn = 0;
    for (uint32_t i = 0; i < pn_len; i++) {
        hdr[pn_off + i] ^= mask[1 + i];
        pn = (pn << 8) | hdr[pn_off + i];
    }
    uint8_t nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 4; i++) nonce[11 - i] ^= (uint8_t)(pn >> (8 * i));

    const uint8_t *ct = d + pn_off + pn_len;
    int ctl = (int)(plen - pn_len - 16);
    if (ctl <= 0 || ctl > 1500) return DPI_NO;
    uint8_t pt[1500];
    if (!aes_gcm_open(key, nonce, hdr, (int)(pn_off + pn_len), ct, ctl, ct + ctl, pt)) {
        quic_decrypt_fail++;
        return DPI_NO;
    }
    quic_decrypt_ok++;

    /* walk frames, feed CRYPTO data into the reassembly buffer */
    uint32_t p = 0, ptn = (uint32_t)ctl;
    while (p < ptn) {
        uint64_t ft;
        int fk = varint(pt + p, ptn - p, &ft);
        if (!fk) break;
        p += (uint32_t)fk;
        if (ft == 0x00 || ft == 0x01) continue;                    /* PADDING, PING */
        if (ft == 0x06) {                                          /* CRYPTO */
            uint64_t off, len;
            int a = varint(pt + p, ptn - p, &off);
            if (!a) break;
            p += (uint32_t)a;
            int b = varint(pt + p, ptn - p, &len);
            if (!b || len > ptn - p - (uint32_t)b) break;
            p += (uint32_t)b;
            if (off < REASM_CAP) reasm_put(rb, (uint32_t)off, pt + p, (uint32_t)len);
            p += (uint32_t)len;
            continue;
        }
        if (ft == 0x02 || ft == 0x03) {                            /* ACK */
            uint64_t v, cnt;
            int a, ok = 1;
            for (int i = 0; i < 2 && ok; i++) { a = varint(pt + p, ptn - p, &v); ok = a; p += (uint32_t)a; }
            a = varint(pt + p, ptn - p, &cnt); if (!a || !ok) break; p += (uint32_t)a;
            a = varint(pt + p, ptn - p, &v); if (!a) break; p += (uint32_t)a;
            for (uint64_t i = 0; i < cnt * 2 + (ft == 0x03 ? 3 : 0) && ok; i++) {
                a = varint(pt + p, ptn - p, &v); ok = a; p += (uint32_t)a;
            }
            if (!ok) break;
            continue;
        }
        break;                                   /* CONNECTION_CLOSE or anything else */
    }
    dpi_res_t r = dpi_tls_handshake_sni(rb->data, rb->contig, host, hostsz);
    return r == DPI_NO ? DPI_MATCH : r;          /* decrypted fine: it IS QUIC either way */
}
