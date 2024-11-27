#include "sha256.h"

/*
 * sha256 constants table from RFC6234
 */
static uint32_t sha256_table[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * get a 32bit unsigned int from a big-endian sha256 byte array
 */
static uint32_t sha_get_dword(t_sha256 *sha, uint32_t index)
{
    index *= 4;
    return ((uint32_t)sha->data[index] << 24)
        | ((uint32_t)sha->data[index + 1] << 16)
        | ((uint32_t)sha->data[index + 2] << 8)
        | (uint32_t)sha->data[index + 3];
}

/*
 * right rotation on a 32bit unsigned int
 */
static uint32_t sha_right_rot(uint32_t num, uint32_t rot)
{
    return (num >> rot) | (num << (32 - rot));
}

/*
 * initialize an sha256 data chunk
 */
void sha256_initialize(t_sha256 *sha)
{
    sha->hash[0] = 0x6a09e667;
    sha->hash[1] = 0xbb67ae85;
    sha->hash[2] = 0x3c6ef372;
    sha->hash[3] = 0xa54ff53a;
    sha->hash[4] = 0x510e527f;
    sha->hash[5] = 0x9b05688c;
    sha->hash[6] = 0x1f83d9ab;
    sha->hash[7] = 0x5be0cd19;
    sha->bytes = 0;
    sha->bits = 0;
}

/*
 * perform the sha256 calculation on a 512 byte chunk
 * assumes that the chunk is fully padded
 */
static void sha256_calculate(t_sha256 *sha)
{
    uint32_t W[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t s0, s1, t1, t2;
    uint32_t i;

    for (i = 0; i < 16; i++)
        W[i] = sha_get_dword(sha, i);

    for (i = 16; i < 64; i++)
    {
        s0 = sha_right_rot(W[i - 15], 7) ^ sha_right_rot(W[i - 15], 18) ^ (W[i - 15] >> 3);
        s1 = sha_right_rot(W[i - 2], 17) ^ sha_right_rot(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    A = sha->hash[0];
    B = sha->hash[1];
    C = sha->hash[2];
    D = sha->hash[3];
    E = sha->hash[4];
    F = sha->hash[5];
    G = sha->hash[6];
    H = sha->hash[7];

    for (i = 0; i < 64; i++)
    {
        s1 = sha_right_rot(E, 6) ^ sha_right_rot(E, 11) ^ sha_right_rot(E, 25);
        t1 = H + s1 + ((E & F) ^ ((~E) & G)) + sha256_table[i] + W[i];
        s0 = sha_right_rot(A, 2) ^ sha_right_rot(A, 13) ^ sha_right_rot(A, 22);
        t2 = s0 + ((A & B) ^ (A & C) ^ (B & C));

        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
    }

    sha->hash[0] += A;
    sha->hash[1] += B;
    sha->hash[2] += C;
    sha->hash[3] += D;
    sha->hash[4] += E;
    sha->hash[5] += F;
    sha->hash[6] += G;
    sha->hash[7] += H;

    sha->bytes = 0;
}

/*
 * add a byte to a sha256 data chunk
 * will automatically process the chunk when full
 */
void sha256_add_byte(t_sha256 *sha, uint8_t byte)
{
    sha->data[sha->bytes] = byte;
    sha->bits += 8;
    sha->bytes += 1;
    // when the chunk is full calculate it
    // sha256_finalize assumes that the chunk is never full
    if (sha->bytes == 64)
        sha256_calculate(sha);
}

/*
 * pad and process the remaining sha256 data chunk
 * after calling this function bytes can no longer be added to it
 */
void sha256_finalize(t_sha256 *sha)
{
    uint32_t i;

    // add 1 bit to end
    sha->data[sha->bytes] = 0x80;
    // padding with 1 bit must always be done
    // if current chunk is greater than 56 bytes
    // it must be completely padded to 64 bytes and calculated first
    // then the next chunk padded with all zero upto 56 bytes
    if (sha->bytes >= 56)
    {
        // zero until 512 bits
        for (i = sha->bytes + 1; i < 64; i++)
            sha->data[i] = 0;
        // calculate the complete chunk
        sha256_calculate(sha);
        // zero first byte of chunk because next section will skip it
        sha->data[0] = 0;
    }
    // zero until 448 bits
    for (i = sha->bytes + 1; i < 56; i++)
        sha->data[i] = 0;
    // copy bit count to end as big-endian
    sha->data[56] = sha->bits >> 56;
    sha->data[57] = (sha->bits >> 48) & 0xff;
    sha->data[58] = (sha->bits >> 40) & 0xff;
    sha->data[59] = (sha->bits >> 32) & 0xff;
    sha->data[60] = (sha->bits >> 24) & 0xff;
    sha->data[61] = (sha->bits >> 16) & 0xff;
    sha->data[62] = (sha->bits >> 8) & 0xff;
    sha->data[63] = sha->bits & 0xff;
    // calculate the complete chunk
    sha256_calculate(sha);
}

/*
 * convert the sha256 digest to a string
 * dst must have at least 65 bytes for the digest and null
 */
void sha256_string(t_sha256 *sha, char *dst)
{
    char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 8; i++)
    {
        dst[0] = hex[sha->hash[i] >> 28];
        dst[1] = hex[(sha->hash[i] >> 24) & 0xf];
        dst[2] = hex[(sha->hash[i] >> 20) & 0xf];
        dst[3] = hex[(sha->hash[i] >> 16) & 0xf];
        dst[4] = hex[(sha->hash[i] >> 12) & 0xf];
        dst[5] = hex[(sha->hash[i] >> 8) & 0xf];
        dst[6] = hex[(sha->hash[i] >> 4) & 0xf];
        dst[7] = hex[sha->hash[i] & 0xf];
        dst += 8;
    }
    *dst = '\0';
}
