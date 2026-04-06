// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT
//
// NSEC3 iterated SHA-1 (RFC 5155) — one thread per label.
// Wire format is precomputed on the CPU (same as engine/nsec3hash.go).

#include <metal_stdlib>
using namespace metal;

inline uint32_t rotl32(uint32_t x, uint n) { return (x << n) | (x >> (32 - n)); }

void sha1_process_block(thread uint32_t h[5], const thread uint8_t chunk[64]) {
    uint32_t w[80];
    for (uint i = 0; i < 16; i++) {
        w[i] = ((uint32_t)chunk[i * 4] << 24) | ((uint32_t)chunk[i * 4 + 1] << 16) |
               ((uint32_t)chunk[i * 4 + 2] << 8) | (uint32_t)chunk[i * 4 + 3];
    }
    for (uint i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    for (uint i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// Max message 256 bytes (enough for NSEC3 wire + salt in benchmark).
void sha1_digest(const thread uint8_t *msg, uint len, thread uint8_t out[20]) {
    uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    uint8_t block[64];

    uint pos = 0;
    while (pos + 64 <= len) {
        for (uint i = 0; i < 64; i++) block[i] = msg[pos + i];
        sha1_process_block(h, block);
        pos += 64;
    }

    uint rem = len - pos;
    uint64_t bitlen = (uint64_t)len * 8ULL;

    for (uint i = 0; i < 64; i++) block[i] = 0;
    for (uint i = 0; i < rem; i++) block[i] = msg[pos + i];
    block[rem] = 0x80;

    if (rem < 56) {
        block[56] = (uint8_t)((bitlen >> 56) & 0xFF);
        block[57] = (uint8_t)((bitlen >> 48) & 0xFF);
        block[58] = (uint8_t)((bitlen >> 40) & 0xFF);
        block[59] = (uint8_t)((bitlen >> 32) & 0xFF);
        block[60] = (uint8_t)((bitlen >> 24) & 0xFF);
        block[61] = (uint8_t)((bitlen >> 16) & 0xFF);
        block[62] = (uint8_t)((bitlen >> 8) & 0xFF);
        block[63] = (uint8_t)(bitlen & 0xFF);
        sha1_process_block(h, block);
    } else {
        sha1_process_block(h, block);
        for (uint i = 0; i < 64; i++) block[i] = 0;
        block[56] = (uint8_t)((bitlen >> 56) & 0xFF);
        block[57] = (uint8_t)((bitlen >> 48) & 0xFF);
        block[58] = (uint8_t)((bitlen >> 40) & 0xFF);
        block[59] = (uint8_t)((bitlen >> 32) & 0xFF);
        block[60] = (uint8_t)((bitlen >> 24) & 0xFF);
        block[61] = (uint8_t)((bitlen >> 16) & 0xFF);
        block[62] = (uint8_t)((bitlen >> 8) & 0xFF);
        block[63] = (uint8_t)(bitlen & 0xFF);
        sha1_process_block(h, block);
    }

    for (uint i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)((h[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (uint8_t)((h[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((h[i] >> 8) & 0xFF);
        out[i * 4 + 3] = (uint8_t)(h[i] & 0xFF);
    }
}

kernel void nsec3_benchmark_kernel(
    device const uchar *wire_blob [[buffer(0)]],
    device const uint *wire_offsets [[buffer(1)]],
    device const uint *wire_lengths [[buffer(2)]],
    device const uchar *salt [[buffer(3)]],
    constant uint &salt_len [[buffer(4)]],
    constant uint &nsec3_iterations [[buffer(5)]],
    device uchar *digests_out [[buffer(6)]],
    uint gid [[thread_position_in_grid]])
{
    uint off = wire_offsets[gid];
    uint wlen = wire_lengths[gid];

    uchar buf[256];
    uchar digest[20];

    uint blen = wlen + salt_len;
    for (uint i = 0; i < wlen; i++) buf[i] = wire_blob[off + i];
    for (uint i = 0; i < salt_len; i++) buf[wlen + i] = salt[i];

    sha1_digest(buf, blen, digest);

    for (uint it = 0u; it < nsec3_iterations; it++) {
        for (uint i = 0; i < 20; i++) buf[i] = digest[i];
        for (uint i = 0; i < salt_len; i++) buf[20 + i] = salt[i];
        sha1_digest(buf, 20 + salt_len, digest);
    }

    for (uint i = 0; i < 20; i++) digests_out[gid * 20 + i] = digest[i];
}
