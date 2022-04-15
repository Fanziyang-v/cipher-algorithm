#ifndef __TDES_H__
#define __TDES_H__

#include "des.h"

typedef enum
{
    EDE2, EDE3, EEE2, EEE3
} TripleDesMode;

/* Encrypt plaintext by 3DES */
long encrypt3des(long plaintext, long** keys, TripleDesMode mode);

/* Decrypt plaintext by 3DES */
long decrypt3des(long ciphertext, long** keys, TripleDesMode mode);

#endif


