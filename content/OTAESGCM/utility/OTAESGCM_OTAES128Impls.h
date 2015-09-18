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

/* OpenTRV OTAESGCM microcontroller-/IoT- friendly AES128 implementations. */

#ifndef ARDUINO_LIB_OTAESGCM_OTAES128IMPLS_H
#define ARDUINO_LIB_OTAESGCM_OTAES128IMPLS_H

// Get available AES API.
#include "OTAESGCM_OTAES128.h"

// Implementations.
#if defined(__AVR_ARCH__) || defined(ARDUINO_ARCH_AVR) // Atmel AVR only.
#include "OTAESGCM_OTAES128AVR.h"
// Fast, small and default implementations, enc and enc+dec, for this architecture.
namespace OTAESGCM
    {
    typedef OTAES128E_AVR OTAES128E_fast_t;
    typedef OTAES128E_AVR OTAES128E_small_t;
    typedef OTAES128E_AVR OTAES128E_default_t;
    typedef OTAES128DE_AVR OTAES128DE_fast_t;
    typedef OTAES128DE_AVR OTAES128DE_small_t;
    typedef OTAES128DE_AVR OTAES128DE_default_t;
    }
#endif

#endif
