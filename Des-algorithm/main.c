#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "des.h"
#include "tdes.h"
#include "util.h"
#include "blockcipher.h"

void printHelp()
{
    printf("Usage:        ./des [-h] [-t] -dm <3DES-Mode> -bm <Block-Cipher-Mode> -k2 <key1> <key2> \
-k3 <key1> <key2> <key3> -f <srcfile> -ef <encryptfil0e> -df <decryptfile>\n");
    printf("Options:\n");
    printf("  -h                         Print Usage\n");
    printf("  -t                         Print encrypt time\n");
    printf("  -dm  <3DES-Mode>           Select 3des mode[EDE2, EDE3, EEE2, EEE3\n");
    printf("  -bm  <Block-Cipher-Mode>   Select Block cipher mode[ECB, CBC, CFB, OFB, CTR]\n");
    printf("  -k2  <key1> <key2>         input 2 key\n");
    printf("  -k3  <key1> <key2> <key3>  input 3 keys\n");
    printf("  -f   <srcfile>             input srcfile path\n");
    printf("  -ef  <encryptfile>         input encryptfile path\n");
    printf("  -df  <decryptfile>         input decryptfile path\n");
}

int main(int argc, char* argv[])
{
    int i, j;
    /* Key Aoumnt. */
    int keyamt = 0;
    /* print encrypt time- defualt false */
    int pt = 0;

    long** keys = (long **)malloc(3 * sizeof(long*));
    /* Block cipher mode and triple des mode */
    BlockCipherMode bm;
    TripleDesMode dm;
    char* srcfile = NULL;
    char* encryptfile = NULL;
    char* decryptfile = NULL;

    /* Record encrypt time */
    clock_t t;
    long fsize;
    /* file stream */
    FILE* src1 = NULL;
    FILE* src2 = NULL;
    FILE* dst1 = NULL;
    FILE* dst2 = NULL;
    
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            printHelp();
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "-t") == 0) {
            /* Print encrypt time */
            pt = 1;
        } else if (strcmp(argv[i], "-k2") == 0) {
            for (j = i + 1; j < i + 3 && j < argc; j++) {
                if (strlen(argv[j]) != 8) {
                    printf("Key-%d: %s, length is not equal to 8!\n", (j - i), argv[j]);
                    exit(EXIT_FAILURE);
                }
                keys[keyamt++] = generateKey(charstol(argv[j]));
            }
            if (keyamt < 2) {
                printf("Key amount is not equal to 2.\n");
                exit(EXIT_FAILURE);
            }

            i += keyamt;

        } else if (strcmp(argv[i], "-k3") == 0) {
            for (j = i + 1; j < i + 4 && j < argc; j++) {
                if (strlen(argv[j]) != 8) {
                    printf("Key-%d: %s, length is not equal to 8!\n", (j - i), argv[j]);
                    exit(EXIT_FAILURE);
                }
                keys[keyamt++] = generateKey(charstol(argv[j]));
            }
            if (keyamt < 3) {
                printf("Key amount is not equal to 3.\n");
                exit(EXIT_FAILURE);
            }

            i += keyamt;
        } else if (strcmp(argv[i], "-dm") == 0) {
            i++;
            assert(i < argc);
            if (strcmp(argv[i], "EDE2") == 0) {
                dm = EDE2;
            } else if (strcmp(argv[i], "EDE3") == 0) {
                dm = EDE3;
            } else if (strcmp(argv[i], "EEE2") == 0) {
                dm = EEE2;
            } else if (strcmp(argv[i], "EEE3") == 0) {
                dm = EEE3;
            } else {
                printf("There is no 3DES mode: %s, it must be [EDE2, EDE3, EEE2, EEE3] \n");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(argv[i], "-bm") == 0) {
            i++;
            assert(i < argc);
            if (strcmp(argv[i], "ECB") == 0) {
                bm = ECB;
            } else if (strcmp(argv[i], "CBC") == 0) {
                bm = CBC;
            } else if (strcmp(argv[i], "CFB") == 0) {
                bm = CFB;
            } else if (strcmp(argv[i], "OFB") == 0) {
                bm = OFB;
            } else if (strcmp(argv[i], "CTR") == 0) {
                bm = CTR;
            } else {
                printf("There is no block cipher mode: %s, it must be [ECB, CBC, CFB, OFB, CTR]\n");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(argv[i], "-f") == 0) {
            i++;
            assert(i < argc);
            srcfile = argv[i];
        } else if (strcmp(argv[i], "-ef") == 0) {
            i++;
            assert(i < argc);
            encryptfile = argv[i];
        } else if (strcmp(argv[i], "-df") == 0) {
            i++;
            assert(i < argc);
            decryptfile = argv[i];
        } else {
            printf("There is no option: %s, use the -h option to check the usage. \n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }

    /* Check validation */
    if (keyamt == 0) {
        printf("You don't input cipher key!\n");
        exit(EXIT_FAILURE);
    }
    if ((dm == EDE3 || dm == EEE3) && keyamt == 2) {
        printf("You need to input 3 cipher key to use this 3DES mode!\n");
    }

    /* Check input file path validation. */
    if (srcfile == NULL) {
        printf("you don't input srcfile path!\n");
        exit(EXIT_FAILURE);
    }

    if (encryptfile == NULL) {
        printf("you don't use -ef option to input a encryptfile path!\n");
        exit(EXIT_FAILURE);
    }

    if (decryptfile == NULL) {
        printf("you don't use -df option to input a encryptfile path!\n");
        exit(EXIT_FAILURE);
    }

    /*  Open the files */
    if ((src1 = fopen(srcfile, "r")) == NULL) {
        printf("Can not Open file: %s\n", srcfile);
        exit(EXIT_FAILURE);
    }
    if ((dst1 = fopen(encryptfile, "w")) == NULL) {
        printf("Can not Open file: %s\n", encryptfile);
        exit(EXIT_FAILURE);
    }

    if ((dst2 = fopen(decryptfile, "w")) == NULL) {
        printf("Can not Open file: %s\n", decryptfile);
        exit(EXIT_FAILURE);
    }

    /* Get File size (bytes) */
    fseek(src1, 0, SEEK_END);
    fsize = ftell(src1);
    rewind(src1);
    printf("srcfile size: %ld bytes.\n", fsize);

    /* encrypt*/
    t = clock();
    /* Set Block cipher mode and 3DES mode */
    encrypt(src1, dst1, bm, keys, dm);
    t = clock() - t;
    if (pt) { printf("Encrypt time: %f s\n", ((float)t)/CLOCKS_PER_SEC); }
    
    fclose(src1);
    fclose(dst1);


    /* Reopen encryption file. */
    if ((src2 = fopen(encryptfile, "r")) == NULL) {
        perror("Can not reopen file: encryption.txt");
        exit(2);
    }

    /* Get File size (bytes) */
    fseek(src2, 0, SEEK_END);
    fsize = ftell(src2);
    rewind(src2);
    printf("srcfile size: %ld bytes.\n", fsize);

    t = clock();
    /* Set Block cipher mode and 3DES mode */
    decrypt(src2, dst2, bm, keys, dm);
    t = clock() - t;
    if (pt) { printf("Decrypt time: %f s\n", ((float)t)/CLOCKS_PER_SEC); }

    fclose(src2);
    fclose(dst2);
    return 0;
}