#include "des.h"
#include <stdlib.h>
#include <stdio.h>
/* Extract a number's left or right part, Only Used in Round function */
#define GET_RIGHT32(val) ((val >> 32) & 0xffffffff)
#define GET_LEFT32(val) (val & 0xffffffff)


/* Only use in generateKey. , keys*/
#define ROTATE(val, k)      (val = ((1 << 28) - 1) & ((val << k) | (((val << k) & ((1 << k) - 1) << 28) >> 28)))
#define COMBINE(val, a, b, size)  (val = ((a) | ((long)b << size)))
#define GET_RIGHT28(val)	((val >> 28) & 0xfffffff)
#define GET_LEFT28(val)	    (val & 0xfffffff)

/**
 * @brief Generate 16 keys by key.
 *
 * @param key cipher key
 * @return long* sub keys array
 */
long* generateKey(long key)
{
    int i, j;
    int pos;
    long pkey = 0;
    long subkey;
    int l, r;
    long* keys = (long*)malloc(ITERATION_TIMES * sizeof(long));

    /* PC_1 - Check */
    for (i = 0; i < CIPHER_KEY_SIZE; i++) {
        if (GET(key, PC_1[i])) {
            SET(pkey, (i+1));
        }
    }
	
    /* Extract left and right 28 bits of pkey.- Check  */
    l = GET_LEFT28(pkey);
    r = GET_RIGHT28(pkey);
	
    /* Generate 16 sub keys */
    for (i = 0; i < ITERATION_TIMES; i++) {
        /* Rotate left- Check */
        ROTATE(l, RL[i]);
        ROTATE(r, RL[i]);
        /* Combine into 56 bits sub key */
        COMBINE(pkey, l, r, 28);
        subkey = 0;
        /* PC_2- Check */
        for (j = 0; j < ROUND_KEY_SIZE; j++) {

            if (GET(pkey, PC_2[j])) {
                SET(subkey, (j+1));
            }
        }
        keys[i] = subkey;
    }

    return keys;
}

/**
 * @brief Des Round function
 *
 * @param r the right 28 bits
 * @param subkey Des 48 bits sub key
 * @param iter Iteration time, to determine use which S Box.
 * @return int f result
 */
long f(long r, long subkey) {
    int i;
    long tmp;
    long res;
    /* Use in Substitue */
    int num;
    int row, col;

    tmp = 0;
    /* Expansive Permutation- Check */
    for (i = 0; i < ROUND_KEY_SIZE; i++) {
        if (GET(r, EP[i])) {
            SET(tmp, (i+1));
        }
    }
    /* Round key add- Check */
    res = tmp ^ subkey;

    tmp = 0;
    /* Substitute-Check */
    for (i = 0; i < 8; i++) {
        /* Extract 6 bits- Check */
        num = (res >> (i * 6)) & 0x3f;
        /* Get row and col in S Box- Check */
        col = (num >> 1) & 0xf;
        row = ((num >> 4) & 0x2) | (num & 0x1);

        /* Combine each 4 bits- Check */
        tmp |= (S[i][row*16+col] << (i * 4));


    }

    res = 0;
    /* Permutation- Check */
        for (i = 0; i < HALF_BLOCK_SIZE; i++) {
            if (GET(tmp, P[i])) {
                SET(res, (i+1));
            }
        }

    return res;
}

/**
 * @brief Encrypt 64 bits data
 *
 * @param plaintext plaintext 64 bits
 * @param keys 16 subkeys (each 48bits)
 * @return long ciphertext 64 bits
 */
long encryptdes(long plaintext, long* keys)
{
    int i, j;
    long l, r, tmp;
    long ptext;
    long ciphertext;

    ptext = 0;
    /* Initial Permutation- Check */
    for (i = 0; i < BLOCK_SIZE; i++) {
        if (GET(plaintext, IP[i])) {
            SET(ptext, (i+1));
        }
    }

    /* Extract left and right 32 bits- Check */
    l = GET_LEFT32(ptext);
    r = GET_RIGHT32(ptext);

    /* Iterate 16 times- Check */
    for (i = 0; i < ITERATION_TIMES; i++) {
        tmp = r;
        r = l ^ f(r, keys[i]);
        l = tmp;
    }

    COMBINE(ptext, l, r, 32);
    ciphertext = 0;
    /* Inverse Initial Permutation */
    for (i = 0; i < BLOCK_SIZE; i++) {
        if (GET(ptext, INV_IP[i])) {
            SET(ciphertext, (i+1));
        }
    }
    /* free memory */
    //free(keys);

    return ciphertext;
}

long decryptdes(long ciphertext, long* keys)
{
    int i, j;
    long l, r, tmp;
    long ptext;
    long plaintext;

    ptext = 0;
    /* Initial Permutation */
    for (i = 0; i < BLOCK_SIZE; i++) {
        if (GET(ciphertext, IP[i])) {
            SET(ptext, (i+1));
        }
    }

    l = GET_LEFT32(ptext);
    r = GET_RIGHT32(ptext);


    /* Iterate 16 times */
    for (i = 0; i < ITERATION_TIMES; i++) {
        tmp = l;
        l = r ^ f(l, keys[ITERATION_TIMES - i - 1]);
        r = tmp;
    }

    COMBINE(ptext, l, r, 32);
    plaintext = 0;
    /* Inverse Initial Permutation */
    for (i = 0; i < BLOCK_SIZE; i++) {
        if (GET(ptext, INV_IP[i])) {
            SET(plaintext, (i+1));
        }
    }

    /* free memory */
    //free(keys);

    return plaintext;
}


