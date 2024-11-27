#ifndef LIBFT_H
#define LIBFT_H

#include <stddef.h>

size_t ft_strlen(const char *s);
int ft_strcmp(const char *s1, const char *s2);
char *ft_strcpy(char *dst, const char *src);
char *ft_strcat(char *dst, const char *src);
void ft_putstr(int n, ...);
void ft_puterr(int n, ...);

#endif
