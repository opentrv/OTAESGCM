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

#ifndef ARDUINO_LIB_OTAESGCM_OTAES128_H
#define ARDUINO_LIB_OTAESGCM_OTAES128_H

#include <stddef.h>
#include <stdint.h>


// Use namespaces to help avoid collisions.
namespace OTAESGCM
    {

// TODO

    }



#define AES_128		// excludes untested parts of the library used for AES256
#define NO_DECRYPT	// excludes decryption functions which are unnecessary when using GCM authentication
//#define MULTIPLY_AS_A_FUNCTION	// This may reduce code size on the keil arm compiler

#include <stdint.h>

void AES128_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);

#ifndef NO_DECRYPT
void AES128_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output);
#endif // NO_DECRYPT




#endif
