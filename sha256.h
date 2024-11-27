#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

typedef struct s_sha256
{
    uint8_t data[64];
    uint32_t hash[8];
    uint32_t bytes;
    uint64_t bits;
} t_sha256;

void sha256_initialize(t_sha256 *sha);
void sha256_add_byte(t_sha256 *sha, uint8_t byte);
void sha256_finalize(t_sha256 *sha);
void sha256_string(t_sha256 *sha, char *dst);

#endif
