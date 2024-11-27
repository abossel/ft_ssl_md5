#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char **argv)
{
    char set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789";
    int len;
    int num;
    int i;

    if (argc != 2)
        return 0;

    srand(time(NULL));
    num = atoi(argv[1]);
    len = strlen(set);
    for (i = 0; i < num; i++)
        printf("%c", set[rand() % len]);
    printf("\n");
    return 0;
}
