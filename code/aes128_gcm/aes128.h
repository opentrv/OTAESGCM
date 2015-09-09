/**
 * aes128.h
 *
 *  Created on: 28 Aug 2015
 *      Author: denzo
 *      modified from tiny-AES128-C library by Kokke
 *  @todo	convert to c++?
 *      	convert sbox, rsbox and rcon getters to use pgmspace macros
 */

/*******************************************************
 * @todo	How To Use This Library
 * *****************************************************
 *
 *
 *
 */

#ifndef AES128_H_
#define AES128_H_

#define AES_128		// excludes untested parts of the library used for AES256
#define NO_DECRYPT	// excludes decryption functions which are unnecessary when using GCM authentication
//#define MULTIPLY_AS_A_FUNCTION	// This may reduce code size on the keil arm compiler

#include <stdint.h>

void AES128_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);

#ifndef NO_DECRYPT
void AES128_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);
#endif // NO_DECRYPT

#endif // AES128_H_
