#ifndef MD5_H
#define MD5_H

#include <stdint.h>

typedef struct s_md5
{
    uint8_t data[64];
    uint32_t abcd[4];
    uint32_t bytes;
    uint64_t bits;
} t_md5;

void md5_initialize(t_md5 *md5);
void md5_add_byte(t_md5 *md5, uint8_t byte);
void md5_finalize(t_md5 *md5);
void md5_string(t_md5 *md5, char *dst);

#endif
