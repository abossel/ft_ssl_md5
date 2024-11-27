#include "dynar.h"

static int dynar_grow(t_dynar *array, size_t capacity)
{
    size_t capacity2;
    char *buffer2;
    size_t i;

    if (capacity <= array->capacity)
        return 1;
    capacity2 = (capacity + 1048576) / 1048576 * 1048576;
    buffer2 = malloc(capacity2);
    if (buffer2 == NULL)
        return 0;
    for (i = 0; i < array->capacity; i++)
        buffer2[i] = array->buffer[i];
    free(array->buffer);
    array->buffer = buffer2;
    array->capacity = capacity2;
    return 1;
}

int dynar_init(t_dynar *array)
{
    array->buffer = NULL;
    array->capacity = 0;
    array->size = 0;
    if (!dynar_grow(array, 1))
        return 0;
    array->buffer[0] = '\0';
    return 1;
}

void dynar_free(t_dynar *array)
{
    free(array->buffer);
    array->buffer = NULL;
    array->capacity = 0;
    array->size = 0;
}

int dynar_append(t_dynar *array, char *buffer, size_t size)
{
    size_t i;

    if (array->capacity < array->size + size + 1)
        if (!dynar_grow(array, array->size + size + 1))
            return 0;
    for (i = 0; i < size; i++)
        array->buffer[array->size + i] = buffer[i];
    array->size += size;
    array->buffer[array->size] = '\0';
    return 1;
}

int dynar_back(t_dynar *array)
{
    if (array->size > 0)
        return array->buffer[array->size - 1];
    return -1;
}

void dynar_remove(t_dynar *array, size_t size)
{
    if (size == 0)
        return;
    if (size > array->size)
        size = array->size;
    array->size -= size;
    array->buffer[array->size] = '\0';
}
