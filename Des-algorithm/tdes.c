#include "tdes.h"

/**
 * @brief 3DES
 * E(K1, D(K2, E(K1, M)))
 * 
 */

/**
 * @brief Encrypt plaintext by 3DES
 * 
 * @param plaintext plaintext
 * @param keys keys
 * @param mode 3DES Mode
 * @return long ciphertext
 */
long encrypt3des(long plaintext, long** keys, TripleDesMode mode)
{
    if (mode == EDE2) {
        return encryptdes(decryptdes(encryptdes(plaintext, keys[0]), keys[1]), keys[0]);
    } else if (mode == EDE3) {
        return encryptdes(decryptdes(encryptdes(plaintext, keys[0]), keys[1]), keys[2]);
    } else if (mode == EEE2) {
        return encryptdes(encryptdes(encryptdes(plaintext, keys[0]), keys[1]), keys[0]);
    } else {
        /* EEE3_MODE */
        return encryptdes(encryptdes(encryptdes(plaintext, keys[0]), keys[1]), keys[2]);
    }

}

/**
 * @brief decrypt ciphertext by 3DES
 * 
 * @param ciphertext plaintext
 * @param key1 keys
 * @param key2 
 * @return long 
 */
long decrypt3des(long ciphertext, long** keys, TripleDesMode mode)
{
    if (mode == EDE2) {
        return decryptdes(encryptdes(decryptdes(ciphertext, keys[0]), keys[1]), keys[0]);
    } else if (mode == EDE3) {
        return decryptdes(encryptdes(decryptdes(ciphertext, keys[2]), keys[1]), keys[0]);
    } else if (mode == EEE2) {
        return decryptdes(decryptdes(decryptdes(ciphertext, keys[0]), keys[1]), keys[0]);
    } else {
        /* EEE3_MODE */
        return decryptdes(decryptdes(decryptdes(ciphertext, keys[2]), keys[1]), keys[0]);
    }
}

