#ifndef DYNAR_H
#define DYNAR_H

#include <stdlib.h>

typedef struct s_dynar
{
    char *buffer;
    size_t capacity;
    size_t size;
} t_dynar;

int dynar_init(t_dynar *array);
void dynar_free(t_dynar *array);
int dynar_append(t_dynar *array, char *buffer, size_t size);
int dynar_back(t_dynar *array);
void dynar_remove(t_dynar *array, size_t size);

#endif
