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
                           Damon Hart-Davis 2015--2016
*/

/* Atmel AVR/ATMega (eg ATMega328P) AES(128) implementation. */
/* Also use as generic (small / 8-bit) MCU implementation. */

#ifndef ARDUINO_LIB_OTAESGCM_OTAES128AVR_H
#define ARDUINO_LIB_OTAESGCM_OTAES128AVR_H

#include <stdint.h>
#include <string.h>
#include "OTAESGCM_OTAES128.h"


// Use namespaces to help avoid collisions.
namespace OTAESGCM
    {


    // AVR (8-bit MCU optimised) encrypt-only implementation.
    // Neither re-entrant nor ISR-safe except where stated.
    // Carries workspace but logically no state is carried from one operation to the next.
    // Residual state should be regarded as sensitive, and eg overwritten before being released to heap.
    class OTAES128E_AVR : public OTAES128E
        {
        protected:
            // Size of RoundKey (bytes).
            static constexpr uint8_t RoundKeySize = 176;

            // The AES key (128 bits, 16 bytes); never NULL.
            // Note that Key is space passed in by caller.
            const uint8_t *Key;
            // Intermediate results during decryption.
            typedef uint8_t state_t[4][4];
            // Note that state is space passed in by caller.
            state_t *state;
            // Nr+1 round keys; NULL if insufficient workspace is passed in.
            // Should be cleared before releasing space to (say) heap.
            //uint8_t RoundKey[RoundKeySize];
            uint8_t * const RoundKey;

            void KeyExpansion();
            void AddRoundKey(uint8_t round);
            void SubBytes();
            void ShiftRows();
            void MixColumns();
            void Cipher();

        public:
            // External workspace/scratch required minimum size, unaligned; strictly positive.
            // At the moment just enough to cover the RoundKey.
            // This constant, defined per class, is effectively part of the API.
            static constexpr uint8_t workspaceRequired = RoundKeySize;
//            constexpr uint8_t getWorkspaceRequired() const { return(workspaceRequired); }

            // Construct an instance: supplied workspace must be large enough.
            OTAES128E_AVR(uint8_t *const workspace, uint8_t workspaceLen)
              : RoundKey((workspaceLen >= workspaceRequired) ? workspace : NULL)
                { }

            // Clean up sensitive state and removes pointers to external state.
            // If Key pointer already cleared then assumed to already have been done and is not repeated.
            // NOT YET TESTED.
            void cleanup() { if((NULL != RoundKey) && (NULL != Key)) { memset(RoundKey, 0, RoundKeySize); state=NULL; Key=NULL; } }

            /**
             *    @brief    AES128 block encryption
             *    @param    input takes a pointer to an array containing plaintext, of size 16 bytes; never NULL
             *    @param    key takes a pointer to a 128-bit (16-byte) secret key; never NULL
             *    @param    output takes a pointer to an array to fill with ciphertext, of size 16 bytes; never NULL
             *
             * Cleans up internal sensitive state when done.
             */
            virtual void blockEncrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);

        };

    // AVR decrypt and encrypt implementation.
    // Neither re-entrant nor ISR-safe except where stated.
    // Carries workspace but logically no state is carried from one operation to the next.
    // Residual state should be regarded as sensitive, and eg overwritten before being released to heap.
    class OTAES128DE_AVR final : public OTAES128D, public OTAES128E_AVR
        {
        public:
            // External workspace/scratch required minimum size, unaligned; strictly positive.
            // At the moment just enough to cover the RoundKey.
            // This constant, defined per class, is effectively part of the API.
            static constexpr uint8_t workspaceRequired = OTAES128E_AVR::workspaceRequired;

        protected:
            void InvMixColumns();
            void InvSubBytes();
            void InvShiftRows();
            void InvCipher();

        public:
            // Expose (version of) base-class constructor.
            using OTAES128E_AVR::OTAES128E_AVR;

            /**
             *    @brief    AES128 block decryption
             *    @param    input takes a pointer to an array containing ciphertext, of size 16 bytes; never NULL
             *    @param    key takes a pointer to a 128-bit (16-byte) secret key; never NULL
             *    @param    output takes a pointer to an array to fill with plaintext, of size 16 bytes; never NULL
             *
             * Cleans up internal sensitive state when done.
             */
            virtual void blockDecrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);
        };


    }

#endif
