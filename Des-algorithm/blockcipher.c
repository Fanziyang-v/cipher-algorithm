#include "util.h"
#include "blockcipher.h"
#include <stdlib.h>
#include <math.h>

/* Encrypt in Block Cipher Mode */
void encrypt(FILE* src, FILE* dst, BlockCipherMode bcmode, long** keys, TripleDesMode tripleDesMode)
{
    switch (bcmode)
    {
    case CBC:
        cbcEncrypt(src, dst, keys, tripleDesMode);
        break;
    case CFB:
        cfbEncrypt(src, dst, keys, tripleDesMode);
        break;
    case OFB:
        ofbEncrypt(src, dst, keys, tripleDesMode);
        break;
    case CTR:
        ctrEncrypt(src, dst, keys, tripleDesMode);
        break;
    default:
        ecbEncrypt(src, dst, keys, tripleDesMode);
        break;
    }
}

/* Decrypt in Block Cipher Mode */
void decrypt(FILE* src, FILE* dst, BlockCipherMode bcmode, long** keys, TripleDesMode tripleDesMode)
{
    switch (bcmode)
    {
    case CBC:
        cbcDecrypt(src, dst, keys, tripleDesMode);
        break;
    case CFB:
        cfbDecrypt(src, dst, keys, tripleDesMode);
        break;
    case OFB:
        ofbDecrypt(src, dst, keys, tripleDesMode);
        break;
    case CTR:
        ctrDecrypt(src, dst, keys, tripleDesMode);
        break;
    default:
        ecbDecrypt(src, dst, keys, tripleDesMode);
        break;
    }
}

/* Encrypt in ECB Mode(Basic) */
void ecbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;

    long fsize;
    long ciphertext;
    long plaintext;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Print initial file size. */
    fwrite(ltobytes(fsize), 1, 8, dst);

    /* Read and Encrypt 8 bytes data each time. */
    
    while(!feof(src)) {
        fread(buf, 1, 8, src);
        plaintext = charstol(buf);
        /* Encrypt plaintext by 3DES. */
        ciphertext = encrypt3des(plaintext, keys, tripleDesMode);
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(ltobytes(ciphertext), 1, 8, dst);
    }


    free(buf);
}


void ecbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int count;
    int len;
    long fsize;
    long lastBlockBytes;
    long ciphertext;
    long plaintext;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    /* Get Decyrpted(initial) file size. and block amounts. */
    fread(buf, 1, 8, src);
    fsize = charstol(buf);
    lastBlockBytes = fsize - 8*(fsize/8);
    count = lastBlockBytes == 0 ? (fsize/8) : (fsize/8 + 1);

    i = 0;
    /* Read and Decrypt 8 bytes data each time. */
    fread(buf, 1, 8, src);
    while(!feof(src)) {
        ciphertext = charstol(buf);
        /* Encrypt plaintext by 3DES. */
        plaintext = decrypt3des(ciphertext, keys, tripleDesMode);
        /* Convert ciphertext in bytes and write to dst file. */
        if (++i == count) {
            /* Reach the last block */
            fwrite(ltobytes(plaintext), 1, lastBlockBytes, dst);
            
        } else {
            fwrite(ltobytes(plaintext), 1, 8, dst);
        }
        
        fread(buf, 1, 8, src);
    }

    free(buf);
}


/* Encrypt file in CBC Mode */
void cbcEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{


    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int len;
    long fsize;
    long ciphertext;
    long plaintext;
    long text;
    long vec = IV;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);
    printf("Src file(Plaintext) Size: %ld bytes.\n", fsize);

    /* Print initial file size. */
    fwrite(ltobytes(fsize), 1, 8, dst);

    /* Read and Encrypt 8 bytes data each time. */
    while(!feof(src)) {
        len = fread(buf, 1, 8, src);
        plaintext = charstol(buf);
        /* Plaintext XOR vector */
        text = plaintext ^ vec;
        /* Encrypt plaintext by 3DES. */
        ciphertext = encrypt3des(text, keys, tripleDesMode);
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(ltobytes(ciphertext), 1, 8, dst);
        /* Update vec */
        vec = ciphertext;
        
    }


    free(buf);
}

/* Decrypt file in CBC Mode */
void cbcDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int count;
    int len;
    long fsize;
    long lastBlockBytes;
    long ciphertext;
    long plaintext;

    /* XOR vector */
    long vec = IV;
    long text;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Get Decyrpted(initial) file size. and block amounts. */
    fread(buf, 1, 8, src);
    fsize = charstol(buf);
    lastBlockBytes = fsize - 8*(fsize/8);
    count = lastBlockBytes == 0 ? (fsize/8) : (fsize/8 + 1);

    i = 0;
    /* Read and Decrypt 8 bytes data each time. */
    fread(buf, 1, 8, src);
    while(!feof(src)) {
        ciphertext = charstol(buf);
        /* Encrypt plaintext by 3DES. */
        text = decrypt3des(ciphertext, keys, tripleDesMode);
        /* Get the plaintext */
        plaintext = vec ^ text;
        /* Convert ciphertext in bytes and write to dst file. */
        if (++i == count) {
            /* Reach the last block */
            fwrite(ltobytes(plaintext), 1, lastBlockBytes, dst);
            
        } else {
            fwrite(ltobytes(plaintext), 1, 8, dst);
        }
        fread(buf, 1, 8, src);
        /* Update vec */
        vec = ciphertext;
    }

    free(buf);
}


/* Encrypt file in CFB Mode-- s = 8bits */
void cfbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 1 bytes*/
    char* buf = (char *)malloc(sizeof(char));
    
    int i;
    int len;
    long text;
    /* Shift Register (64 bits) */
    long reg = IV;

    /* Read and Encrypt 8 bytes data each time. */
    len = fread(buf, 1, 1, src);
    while(!feof(src)) {
        /* Encrypt reg by 3DES. */
        text = encrypt3des(reg, keys, tripleDesMode);
        /* Get ciphertext (8 bits ) <==> ciphertext = plaintext ^ text(low 8 bits) */
        buf[0] ^= (char)text;
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(buf, 1, 1, dst);
        /* Update shift register(Cipher Feeback ) */
        reg = (reg << 8) | ((long)buf[0] & 0xff);
        len = fread(buf, 1, 1, src);
    }

    free(buf);
}

/* Decrypt file in CFB Mode */
void cfbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 1 bytes*/
    char* buf = (char *)malloc(sizeof(char));
    
    int i;
    int len;
    long text;
    long fsize;
    /* Shift Register (64 bits) */
    long reg = IV;

    /* Read and Decrypt 1 bytes data each time. */
    len = fread(buf, 1, 1, src);
    while(!feof(src)) {
        /* Encrypt reg by 3DES. */
        text = encrypt3des(reg, keys, tripleDesMode);
        /* Update Shift register by 8 bits ciphertext */
        reg = (reg << 8) | ((long)buf[0] & 0xff);

        /* Get plaintext (8 bits ) <==> plaintext = ciphertext ^ text(low 8 bits) */
        buf[0] ^= (char)text;
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(buf, 1, 1, dst);
        len = fread(buf, 1, 1, src);
    }

    free(buf);
}

/* Encrypt file in OFB Mode */
void ofbEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int len;
    long fsize;
    long ciphertext;
    long plaintext;

    /* The real Encrypt object */
    long text = IV;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Print initial file size. */
    fwrite(ltobytes(fsize), 1, 8, dst);

    /* Read and Encrypt 8 bytes data each time. */
    while(!feof(src)) {
        len = fread(buf, 1, 8, src);
        plaintext = charstol(buf);
        /* Encrypt text by 3DES and update text */
        text = encrypt3des(text, keys, tripleDesMode);
        /* Get ciphertext */
        ciphertext = text ^ plaintext;
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(ltobytes(ciphertext), 1, 8, dst);
    }


    free(buf);
}

/* Decrypt file in OFB Mode */
void ofbDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int count;
    long lastBlockBytes;
    int len;
    long fsize;
    long ciphertext;
    long plaintext;

    /* The real Encrypt object */
    long text = IV;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Get Decyrpted(initial) file size. and block amounts. */
    fread(buf, 1, 8, src);
    fsize = charstol(buf);
    lastBlockBytes = fsize - 8*(fsize/8);
    count = lastBlockBytes == 0 ? (fsize/8) : (fsize/8 + 1);

    i = 0;
    /* Read and Encrypt 8 bytes data each time. */
    len = fread(buf, 1, 8, src);
    while(!feof(src)) {
        ciphertext = charstol(buf);
        /* Encrypt text by 3DES and update text(Output feedback) */
        text = encrypt3des(text, keys, tripleDesMode);
        /* Get ciphertext */
        plaintext = text ^ ciphertext;
        /* Convert ciphertext in bytes and write to dst file. */
        if (++i == count) {
            /* Reach the last block */
            fwrite(ltobytes(plaintext), 1, lastBlockBytes, dst);
        } else {
            fwrite(ltobytes(plaintext), 1, 8, dst);
        }
        
        len = fread(buf, 1, 8, src);
    }


    free(buf);
}


/* Encrypt file in CTR Mode */
void ctrEncrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
    /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int len;
    long fsize;
    long ciphertext;
    long plaintext;
    long text;
    /* counter */
    long counter = IV;
    /* Use Gap to increment counter value. */
    long gap = 7;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Print initial file size. */
    fwrite(ltobytes(fsize), 1, 8, dst);

    /* Read and Encrypt 8 bytes data each time. */
    while(!feof(src)) {
        len = fread(buf, 1, 8, src);
        plaintext = charstol(buf);
        /* Encrypt plaintext by 3DES. */
        text = encrypt3des(counter, keys, tripleDesMode);
        /* Get ciphertext */
        ciphertext = text ^ plaintext;
        /* Convert ciphertext in bytes and write to dst file. */
        fwrite(ltobytes(ciphertext), 1, 8, dst);
        /* Update counter value */
        counter += gap;
    }


    free(buf);
}

/* Decrypt file in CTR Mode */
void ctrDecrypt(FILE* src, FILE* dst, long** keys, TripleDesMode tripleDesMode)
{
   /* Buffer 8 bytes*/
    char* buf;
    
    int i;
    int count;
    int len;
    long fsize;
    long lastBlockBytes;
    long ciphertext;
    long plaintext;
    long text;

    /* Counter value*/
    long counter = IV;
    long gap = 7;

    /* Allocate Memory */
    buf = (char *)malloc(sizeof(char)*8);

    // obtain file size:
    fseek(src , 0 , SEEK_END);
    fsize = ftell(src);
    rewind(src);

    /* Get Decyrpted(initial) file size. and block amounts. */
    fread(buf, 1, 8, src);
    fsize = charstol(buf);
    lastBlockBytes = fsize - 8*(fsize/8);
    count = lastBlockBytes == 0 ? (fsize/8) : (fsize/8 + 1);

    i = 0;
    /* Read and Decrypt 8 bytes data each time. */
    fread(buf, 1, 8, src);
    while(!feof(src)) {
        ciphertext = charstol(buf);
        text = encrypt3des(counter, keys, tripleDesMode);
        /* Get plaintext */
        plaintext = text ^ ciphertext;
        /* Convert ciphertext in bytes and write to dst file. */
        if (++i == count) {
            /* Reach the last block */
            fwrite(ltobytes(plaintext), 1, lastBlockBytes, dst);
            
        } else {
            fwrite(ltobytes(plaintext), 1, 8, dst);
        }
        
        fread(buf, 1, 8, src);
        /* Update Counter value. */
        counter += gap;
    }

    free(buf);
}
