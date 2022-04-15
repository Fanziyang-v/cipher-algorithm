#include "util.h"
#include <stdlib.h>
#include <stdio.h>
/* Only use in Extract key, plaintext and ciphertext */
long charstol(char* s)
{
    int i;
    int len = 8;
    long d;
    long res = 0;
    for (i = 0; i < len; i++) {
        d = (long)s[i] & 0xff;
        res |= (d << (i * 8));
    }
    return res;
}

/* long to chars(outputstring with \0) */
char* ltochars(long l)
{
    int i;
    int len = 8;
    char* s = (char*)malloc((len + 1) * sizeof(char));

    for (i = 0; i < len; i++) {
        s[i] = (l >> (8 * i)) & 0xff;
    }

    s[len] = '\0';
    return s;
}

char* ltobytes(long l)
{
    int i;
    int len = 8;
    char* s = (char*)malloc(len * sizeof(char));

    for (i = 0; i < len; i++) {
        s[i] = (l >> (8 * i)) & 0xff;
    }

    return s;
}