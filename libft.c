#include "libft.h"
#include <unistd.h>
#include <stdarg.h>

size_t ft_strlen(const char *s)
{
    size_t len;

    len = 0;
    while (s[len] != '\0')
        len++;
    return (len);
}

int ft_strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2 && *s1 != '\0')
    {
        s1++;
        s2++;
    }
    if (*(unsigned char *)s1 > *(unsigned char *)s2)
        return (1);
    if (*(unsigned char *)s1 < *(unsigned char *)s2)
        return (-1);
    return (0);
}

char *ft_strcpy(char *dst, const char *src)
{
    char *ret;

    ret = dst;
    while (*src != '\0')
    {
        *dst = *src;
        dst++;
        src++;
    }
    *dst = '\0';
    return (ret);
}

char *ft_strcat(char *dst, const char *src)
{
    char *ret;

    ret = dst;
    while (*dst != '\0')
        dst++;
    ft_strcpy(dst, src);
    return (ret);
}

/*
 * write n number of strings to stdout
 * usage: ft_putstr(3, "abc", "xyz", "\n")
 */
void ft_putstr(int n, ...)
{
    va_list va;
    char *s;

    va_start(va, n);
    while (n--)
    {
        s = va_arg(va, char *);
        if (s != NULL)
            write(STDOUT_FILENO, s, ft_strlen(s));
    }
    va_end(va);
}

/*
 * write n number of strings to stderr
 * usage: ft_puterr(3, "abc", "xyz", "\n")
 */
void ft_puterr(int n, ...)
{
    va_list va;
    char *s;

    va_start(va, n);
    while (n--)
    {
        s = va_arg(va, char *);
        if (s != NULL)
            write(STDERR_FILENO, s, ft_strlen(s));
    }
    va_end(va);
}
