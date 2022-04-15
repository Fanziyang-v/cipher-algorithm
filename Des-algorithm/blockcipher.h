#ifndef __BLOCKCIPHER_H__
#define __BLOCKCIPHER_H__

#include <stdio.h>
#include "tdes.h"

/**
 * @brief Block Cipher Working Mode:
 * ECB: Electronic CodeBook Mode (Basic)
 * CBC: Code Block cipher
 * CFB: Code FeedBack
 * OFB: Ouput FeeBack
 * CTR: Counter Mode
 */


/* Define some */

typedef enum
{
    ECB, CBC, CFB, OFB, CTR
} BlockCipherMode;

/* Initial Vector, 64 bits */
#define IV 0x123456789abcdef0


/* Encrypt file by 3DES using block cipher mode- ECB/CBC/CFB/OFB/CTR */
void encrypt(FILE* src, FILE* dst, BlockCipherMode bcmode, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file by 3DES using block cipher mode- ECB/CBC/CFB/OFB/CTR */
void decrypt(FILE* src, FILE* dst, BlockCipherMode bcmode,  long** keys, TripleDesMode tripleDesMode);


/* Encrypt file in ECB Mode(Basic) */
void ecbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file in ECB Mode(Basic) */
void ecbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Encrypt file in CBC Mode */
void cbcEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file in CBC Mode */
void cbcDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);


/* Encrypt file in CFB Mode */
void cfbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file in CFB Mode */
void cfbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Encrypt file in OFB Mode */
void ofbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file in OFB Mode */
void ofbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);


/* Encrypt file in CTR Mode */
void ctrEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);

/* Decrypt file in CTR Mode */
void ctrDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode);


#endif