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

Author(s) / Copyright (s): Deniz Erbillgin 2015
                           Damon Hart-Davis 2015
*/

/* OpenTRV OTAESGCM microcontroller-/IoT- friendly AES(128)-GCM implementation. */

#ifndef ARDUINO_LIB_OTAESGCM_OTAESGCM_H
#define ARDUINO_LIB_OTAESGCM_OTAESGCM_H

#include <stddef.h>
#include <stdint.h>


// Use namespaces to help avoid collisions.
namespace OTAESGCM
    {


static const uint8_t AES128GCM_BLOCK_SIZE = 16; // GCM block size in bytes. This must be the same as the AES block size.
static const uint8_t AES128GCM_IV_SIZE    = 12; // GCM initialisation size in bytes.
static const uint8_t AES128GCM_TAG_SIZE   = 16; // GCM authentication tag size in bytes.


    // Base class / interface for AES128-GCM encryption/decryption.
    // Neither re-entrant nor ISR-safe except where stated.
    class OTAES128GCM
        {
        protected:
            // Only derived classes can construct an instance.
            OTAES128GCM() { }

        public:
            /**
             * @brief    performs AES-GCM encryption
             * @param    key             pointer to 16 byte (128 bit) key; never NULL
             * @param    IV              pointer to 12 byte (96 bit) IV; never NULL
             * @param    PDATA           pointer to plaintext array; never NULL
             * @param    PDATA_length    length of plaintext array (in bytes?), can be zero
             * @param    ADATA           pointer to additional data array; never NULL
             * @param    ADATA_length    length of additional data (in bytes?), can be zero
             * @param    CDATA           buffer to output ciphertext to, size (at least) PDATA_length; never NULL
             * @param    tag             pointer to 16 byte buffer to output tag to; never NULL
             *
             * @todo CLARIFY which input data (eg PDATA) need to be multiples of block size, if any
             */
            virtual void aes128_gcm_encrypt(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATA, uint8_t PDATALength,
                uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag) = 0;

            /**
             * @brief   performs AES-GCM decryption and authentication
             * @todo    How to do data hiding on authentication fail?
             *                 - when put into classes?
             *                 - wipe array?
             *                 - make PDATA private and then only pass pointer if true?
             * @param    key             pointer to 16 byte (128 bit) key
             * @param    IV              pointer to IV
             * @param    CDATA           pointer to ciphertext array
             * @param    CDATALength     length of ciphertext array
             * @param    ADATA           pointer to additional data array
             * @param    ADATALength     length of additional data
             * @param    PDATA           buffer to output plaintext to
             * @retval   returns true if authenticated, else false
             *
             * @todo CLARIFY which input data (eg CDATA) need to be multiples of block size, if any
             */
            virtual bool aes128_gcm_decrypt(
                 const uint8_t* key, const uint8_t* IV,
                 const uint8_t* CDATA, uint8_t CDATALength,
                 const uint8_t* ADATA, uint8_t ADATALength,
                 const uint8_t* messageTag, uint8_t *PDATA) = 0;

#if 0 // Defining the virtual destructor uses ~800+ bytes of Flash by forcing use of malloc()/free().
            // Ensure safe instance destruction when derived from.
            // by default attempts to shut down the sensor and otherwise free resources when done.
            // This uses ~800+ bytes of Flash by forcing use of malloc()/free().
            virtual ~OTAES128GCM() { }
#else
#define OTAES128GCM_NO_VIRT_DEST // Beware, no virtual destructor so be careful of use via base pointers.
#endif
        };

    // Generic implementation, parameterised with type of underlying AES implementation.
    // This implementation is not specialised for a particular CPU/MCU for example.
    // This implementation is carries no state beyond that of the AES128 implementation.
    class OTAES128GCMGeneric : public OTAES128GCM
        {
        public:
            virtual void aes128_gcm_encrypt(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATA, uint8_t PDATALength,
                uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag);
            virtual bool aes128_gcm_decrypt(
                 const uint8_t* key, const uint8_t* IV,
                 const uint8_t* CDATA, uint8_t CDATALength,
                 const uint8_t* ADATA, uint8_t ADATALength,
                 const uint8_t* messageTag, uint8_t *PDATA);
        };


    }







#endif
