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

Author(s) / Copyright (s): Deniz Erbilgin 2015--2017
                           Damon Hart-Davis 2015--2017
*/

/* OpenTRV OTAESGCM microcontroller-/IoT- friendly AES(128)-GCM implementation. */

#ifndef ARDUINO_LIB_OTAESGCM_OTAES128_H
#define ARDUINO_LIB_OTAESGCM_OTAES128_H

#include <stddef.h>
#include <stdint.h>


// Use namespaces to help avoid collisions.
namespace OTAESGCM
    {


    // Base class / interface for AES128 block encryption only.
    // Implementations can be optimised for different characteristics such as speed or size or CPU.
    // Implementations may contain differing amounts of state / data, ie vary in size.
    // Many uses, eg for AES-GCM, or TX-only leaf nodes, will not require block decryption.
    // Neither re-entrant nor ISR-safe except where stated.
    class OTAES128E
        {
        protected:
            // Only derived classes can construct an instance.
            constexpr OTAES128E() { }

        public:
            /**
             *    @brief    AES128 block encryption
             *    @param    input takes a pointer to an array containing plaintext, of size 16 bytes; never NULL
             *    @param    key takes a pointer to a 128-bit (16-byte) secret key; never NULL
             *    @param    output takes a pointer to an array to fill with ciphertext, of size 16 bytes; never NULL
             */
            virtual void blockEncrypt(const uint8_t* input, const uint8_t* key, uint8_t *output) = 0;

#if 0 // Defining the virtual destructor uses ~800+ bytes of Flash by forcing use of malloc()/free().
            // Ensure safe instance destruction when derived from.
            // by default attempts to shut down the sensor and otherwise free resources when done.
            // This uses ~800+ bytes of Flash by forcing use of malloc()/free().
            virtual ~OTAES128E() { }
#else
#define OTAES128Encrypt_NO_VIRT_DEST // Beware, no virtual destructor so be careful of use via base pointers.
#endif
        };

    // Base class / interface for AES128 block decryption.
    // Implementations can be optimised for different characteristics such as speed or size or CPU.
    // Implementations may contain differing amounts of state / data, ie vary in size.
    // Many uses, eg for AES-GCM, or TX-only leaf nodes, will not require block decryption.
    // Neither re-entrant nor ISR-safe except where stated.
    class OTAES128D
        {
        protected:
            // Only derived classes can construct an instance.
            constexpr OTAES128D() { }

        public:
            /**
             *    @brief    AES128 block decryption
             *    @param    input takes a pointer to an array containing ciphertext, of size 16 bytes; never NULL
             *    @param    key takes a pointer to a 128-bit (16-byte) secret key; never NULL
             *    @param    output takes a pointer to an array to fill with plaintext, of size 16 bytes; never NULL
             */
            virtual void blockDecrypt(const uint8_t* input, const uint8_t* key, uint8_t *output) = 0;
        };


    }


#endif
