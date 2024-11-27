#include "md5.h"

/*
 * MD5 precomputed table from RFC1321
 */
static uint32_t md5_table[64] =
{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/*
 * MD5 shift table from RFC1321
 */
static uint32_t md5_shift[64] =
{
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

/*
 * get a 32bit unsigned int from a little-endian md5 byte array
 */
static uint32_t md5_get_dword(t_md5 *md5, uint32_t index)
{
    index *= 4;
    return ((uint32_t)md5->data[index + 3] << 24)
        | ((uint32_t)md5->data[index + 2] << 16)
        | ((uint32_t)md5->data[index + 1] << 8)
        | (uint32_t)md5->data[index];
}

/*
 * change the endian type of a 32bit unsigned int
 */
static uint32_t md5_swap_endian(uint32_t num)
{
    return (num << 24) | ((num & 0x0000ff00) << 8)
        | ((num & 0x00ff0000) >> 8) | (num >> 24);
}

/*
 * left rotation on a 32bit unsigned int
 */
static uint32_t md5_left_rot(uint32_t num, uint32_t rot)
{
    return (num << rot) | (num >> (32 - rot));
}

/*
 * initialize an md5 data chunk
 */
void md5_initialize(t_md5 *md5)
{
    md5->abcd[0] = 0x67452301;
    md5->abcd[1] = 0xefcdab89;
    md5->abcd[2] = 0x98badcfe;
    md5->abcd[3] = 0x10325476;
    md5->bytes = 0;
    md5->bits = 0;
}

/*
 * perform the md5 calculation on a 512 byte chunk
 * assumes that the chunk is fully padded
 */
static void md5_calculate(t_md5 *md5)
{
    uint32_t A, B, C, D, F, g, i;

    A = md5->abcd[0];
    B = md5->abcd[1];
    C = md5->abcd[2];
    D = md5->abcd[3];
    for (i = 0; i < 64; i++)
    {
        if (i <= 15)
        {
            F = D ^ (B & (C ^ D));
            g = i;
        }
        else if (i >= 16 && i <= 31)
        {
            F = C ^ (D & (B ^ C));
            g = (5 * i + 1) % 16;
        }
        else if (i >= 32 && i <= 47)
        {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        }
        else
        {
            F = C ^ (B | (~D));
            g = (7 * i) % 16;
        }
        F = F + A + md5_table[i] + md5_get_dword(md5, g);
        A = D;
        D = C;
        C = B;
        B = B + md5_left_rot(F, md5_shift[i]);
    }
    md5->abcd[0] += A;
    md5->abcd[1] += B;
    md5->abcd[2] += C;
    md5->abcd[3] += D;

    md5->bytes = 0;
}

/*
 * add a byte to a md5 data chunk
 * will automatically process the chunk when full
 */
void md5_add_byte(t_md5 *md5, uint8_t byte)
{
    md5->data[md5->bytes] = byte;
    md5->bits += 8;
    md5->bytes += 1;
    // when the chunk is full calculate it
    // md5_finalize assumes that the chunk is never full
    if (md5->bytes == 64)
        md5_calculate(md5);
}

/*
 * pad and process the remaining md5 data chunk
 * after calling this function bytes can no longer be added to it
 */
void md5_finalize(t_md5 *md5)
{
    uint32_t i;

    // add 1 bit to end
    md5->data[md5->bytes] = 0x80;
    // padding with 1 bit must always be done
    // if current chunk is greater than 56 bytes
    // it must be completely padded to 64 bytes and calculated first
    // then the next chunk padded with all zero upto 56 bytes
    if (md5->bytes >= 56)
    {
        // zero until 512 bits
        for (i = md5->bytes + 1; i < 64; i++)
            md5->data[i] = 0;
        // calculate the complete chunk
        md5_calculate(md5);
        // zero the first byte because the next section will skip it
        md5->data[0] = 0;
    }
    // zero until 448 bits
    for (i = md5->bytes + 1; i < 56; i++)
        md5->data[i] = 0;
    // copy bit count to end as little-endian
    md5->data[56] = md5->bits & 0xff;
    md5->data[57] = (md5->bits >> 8) & 0xff;
    md5->data[58] = (md5->bits >> 16) & 0xff;
    md5->data[59] = (md5->bits >> 24) & 0xff;
    md5->data[60] = (md5->bits >> 32) & 0xff;
    md5->data[61] = (md5->bits >> 40) & 0xff;
    md5->data[62] = (md5->bits >> 48) & 0xff;
    md5->data[63] = md5->bits >> 56;
    // calculate the complete chunk
    md5_calculate(md5);
}

/*
 * convert the md5 digest to a string
 * dst must have at least 33 bytes for the digest and null
 */
void md5_string(t_md5 *md5, char *dst)
{
    char hex[] = "0123456789abcdef";
    uint32_t num;
    int i;

    for (i = 0; i < 4; i++)
    {
        // change the hash to big endian
        num = md5_swap_endian(md5->abcd[i]);
        dst[0] = hex[num >> 28];
        dst[1] = hex[(num >> 24) & 0xf];
        dst[2] = hex[(num >> 20) & 0xf];
        dst[3] = hex[(num >> 16) & 0xf];
        dst[4] = hex[(num >> 12) & 0xf];
        dst[5] = hex[(num >> 8) & 0xf];
        dst[6] = hex[(num >> 4) & 0xf];
        dst[7] = hex[num & 0xf];
        dst += 8;
    }
    *dst = '\0';
}
