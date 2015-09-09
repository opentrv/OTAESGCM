/*
 * aes128_gcm.h
 *
 *  Created on: 1 Sep 2015
 *      Author: denzo
 */

/*******************************************************
 * @todo	How To Use This Library
 * *****************************************************
 *
 */


#ifndef AES128_GCM_H_
#define AES128_GCM_H_

#include <stdint.h>

#define GCM_BLOCK_SIZE  16	// block size in bytes. This must be the same as the AES block size
#define GCM_IV_SIZE		12
#define GCM_TAG_SIZE	16

bool aes128_gcm_encrypt(    const uint8_t* key, const uint8_t* IV,
                            const uint8_t* PDATA, uint8_t PDATALength,
                            uint8_t* ADATA, uint8_t ADATALength,
                            uint8_t* CDATA, uint8_t *tag);

uint8_t aes128_gcm_decrypt(	const uint8_t* key, const uint8_t* IV,
                            const uint8_t* CDATA, uint8_t CDATALength,
                            const uint8_t* ADATA, uint8_t ADATALength,
                            const uint8_t* messageTag, uint8_t *PDATA);

#endif /* AES128_GCM_H_ */
