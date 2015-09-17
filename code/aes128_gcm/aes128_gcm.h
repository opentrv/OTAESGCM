/*
The OpenTRV project licenses this file to you
under the Apache Licence, Version 2.0 (the "Licence");
you may not use this file except in compliance
with the Licence. You may obtain a copy of the Licence at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the Licence is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the Licence for the
specific language governing permissions and limitations
under the Licence.
Author(s) / Copyright (s): Deniz Erbilgin 2015
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
