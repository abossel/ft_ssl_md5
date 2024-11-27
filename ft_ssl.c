#include "md5.h"
#include "sha256.h"
#include "libft.h"
#include "dynar.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define FT_MD5 1
#define FT_SHA256 2
#define FT_FILES 4
#define FT_PASSTHRU 8
#define FT_QUIET 16
#define FT_REVERSE 32
#define FT_STRING 64
#define FT_STDIN 128

typedef struct s_args
{
    int flags;
    char hash[8];
    char HASH[8];
    char *string;
    char **files;
    t_md5 md5;
    t_sha256 sha;
} t_args;

void error_msg(char *prefix, char *subject, char *message)
{
    ft_puterr(1, "ft_ssl: ");
    if (prefix != NULL)
        ft_puterr(2, prefix, ": ");
    if (subject != NULL)
        ft_puterr(2, subject, ": ");
    if (message != NULL)
        ft_puterr(2, message, "\n");
    else
        ft_puterr(2, strerror(errno), "\n");
}

void error_exit(char *prefix, char *subject, char *message)
{
    error_msg(prefix, subject, message);
    exit(EXIT_FAILURE);
}

void usage_exit(char *prefix, char *subject, char *message)
{
    error_msg(prefix, subject, message);
    ft_puterr(1, "usage: ft_ssl <md5|sha256> [-p -q -r] [-s string] [files ...]\n");
    ft_puterr(1, "options:\n");
    ft_puterr(1, "    -p   echo STDIN to STDOUT and append the checksum to STDOUT\n");
    ft_puterr(1, "    -q   quiet mode\n");
    ft_puterr(1, "    -r   reverse the format of the output\n");
    ft_puterr(1, "    -s   print the sum of the given string\n");
    exit(EXIT_FAILURE);
}

void read_args(int argc, char **argv, t_args *args)
{
    int i;

    args->flags = 0;
    args->hash[0] = '\0';
    args->HASH[0] = '\0';
    args->string = NULL;
    args->files = NULL;

    // check for valid hash function
    if (argc < 2)
        usage_exit(NULL, NULL, "missing hash function");

    // check hash function is valid
    if (ft_strcmp(argv[1], "md5") == 0)
    {
        args->flags |= FT_MD5;
        ft_strcpy(args->hash, "md5");
        ft_strcpy(args->HASH, "MD5");
    }
    else if (ft_strcmp(argv[1], "sha256") == 0)
    {
        args->flags |= FT_SHA256;
        ft_strcpy(args->hash, "sha256");
        ft_strcpy(args->HASH, "SHA256");
    }
    else
        usage_exit(NULL, argv[1], "invalid hash function");

    // loop through options
    for (i = 2; i < argc; i++)
    {
        if (ft_strcmp(argv[i], "-p") == 0)
            args->flags |= FT_PASSTHRU;
        else if (ft_strcmp(argv[i], "-q") == 0)
            args->flags |= FT_QUIET;
        else if (ft_strcmp(argv[i], "-r") == 0)
            args->flags |= FT_REVERSE;
        else if (ft_strcmp(argv[i], "-s") == 0)
        {
            args->flags |= FT_STRING;
            if (argv[i + 1] == NULL)
                usage_exit(args->hash, "-s", "missing string");
            args->string = argv[i + 1];
            i++;
        }
        else
            break;
    }

    // get file name inputs after options
    if (argv[i] != NULL)
    {
        args->flags |= FT_FILES;
        args->files = &argv[i];
    }

    // if no inputs use stdin
    if (!(args->flags & (FT_PASSTHRU | FT_STRING | FT_FILES)))
        args->flags |= FT_STDIN;
}

void hash_initialize(t_args *args)
{
    if (args->flags & FT_MD5)
        md5_initialize(&args->md5);
    else if (args->flags & FT_SHA256)
        sha256_initialize(&args->sha);
}

void hash_add_byte(t_args *args, uint8_t byte)
{
    if (args->flags & FT_MD5)
        md5_add_byte(&args->md5, byte);
    else if (args->flags & FT_SHA256)
        sha256_add_byte(&args->sha, byte);
}

void hash_finalize(t_args *args)
{
    if (args->flags & FT_MD5)
        md5_finalize(&args->md5);
    else if (args->flags & FT_SHA256)
        sha256_finalize(&args->sha);
}

void hash_string(t_args *args, char *dst)
{
    if (args->flags & FT_MD5)
        md5_string(&args->md5, dst);
    else if (args->flags & FT_SHA256)
        sha256_string(&args->sha, dst);
}

void process_string(t_args *args)
{
    char digest[65];
    int len;
    int i;

    len = ft_strlen(args->string);

    hash_initialize(args);
    for (i = 0; i < len; i++)
        hash_add_byte(args, args->string[i]);
    hash_finalize(args);
    hash_string(args, digest);

    if (!(args->flags & (FT_REVERSE | FT_QUIET)))
        ft_putstr(6, args->HASH, " (\"", args->string, "\") = ", digest, "\n");
    else if (args->flags & FT_REVERSE && !(args->flags & FT_QUIET))
        ft_putstr(4, digest, " \"", args->string, "\"\n");
    else
        ft_putstr(2, digest, "\n");
}

int process_file(t_args *args, int fd)
{
    uint8_t buffer[1024];
    char digest[65];
    int len;
    int i;

    hash_initialize(args);
    len = read(fd, buffer, sizeof(buffer));
    while (len > 0)
    {
        for (i = 0; i < len; i++)
            hash_add_byte(args, buffer[i]);
        len = read(fd, buffer, sizeof(buffer));
    }
    if (len < 0)
        return 0;
    hash_finalize(args);
    hash_string(args, digest);

    if (!(args->flags & (FT_REVERSE | FT_QUIET)))
        ft_putstr(6, args->HASH, " (", args->files[0], ") = ", digest, "\n");
    else if (args->flags & FT_REVERSE && !(args->flags & FT_QUIET))
        ft_putstr(4, digest, " ", args->files[0], "\n");
    else
        ft_putstr(2, digest, "\n");

    return 1;
}

int process_stdin(t_args *args)
{
    uint8_t buffer[1024];
    t_dynar array;
    char digest[65];
    int len;
    int i;

    if (!dynar_init(&array))
        return 0;
    hash_initialize(args);
    len = read(STDIN_FILENO, buffer, sizeof(buffer));
    while (len > 0)
    {
        for (i = 0; i < len; i++)
            hash_add_byte(args, buffer[i]);

        if (args->flags & FT_PASSTHRU
            && !dynar_append(&array, (char *)buffer, len))
        {
            dynar_free(&array);
            return 0;
        }

        len = read(STDIN_FILENO, buffer, sizeof(buffer));
    }
    if (len < 0)
        return 0;
    hash_finalize(args);
    hash_string(args, digest);

    // don't print new line on the end
    if (dynar_back(&array) == '\n')
        dynar_remove(&array, 1);

    if (!(args->flags & (FT_PASSTHRU | FT_QUIET)))
        ft_putstr(3, "(stdin)= ", digest, "\n");
    else if (args->flags & FT_PASSTHRU && !(args->flags & FT_QUIET))
        ft_putstr(5, "(\"", array.buffer, "\")= ", digest, "\n");
    else if (args->flags & FT_PASSTHRU && args->flags & FT_QUIET)
        ft_putstr(4, array.buffer, "\n", digest, "\n");
    else
        ft_putstr(2, digest, "\n");
    dynar_free(&array);

    return 1;
}

int main(int argc, char **argv)
{
    t_args args;
    int fd;

    read_args(argc, argv, &args);

    if (args.flags & (FT_PASSTHRU | FT_STDIN))
    {
        if (!process_stdin(&args))
            error_exit(args.hash, "stdin", NULL);
    }
    if (args.flags & FT_STRING)
        process_string(&args);
    if (args.flags & FT_FILES)
    {
        while (args.files[0] != NULL)
        {
            fd = open(args.files[0], O_RDONLY);
            if (fd != -1)
            {
                if (!process_file(&args, fd))
                    error_msg(args.hash, args.files[0], NULL);
                close(fd);
            }
            else
                error_msg(args.hash, args.files[0], NULL);
            args.files = &args.files[1];
        }
    }

    return 0;
}
