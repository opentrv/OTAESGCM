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

#ifndef ARDUINO_LIB_OTAESGCM_H
#define ARDUINO_LIB_OTAESGCM_H

#define ARDUINO_LIB_OTAESGCM_VERSION_MAJOR 0
#define ARDUINO_LIB_OTAESGCM_VERSION_MINOR 2

/* OpenTRV OTAESGCM microcontroller-/IoT- friendly AES(128)-GCM implementation. */

/*
 * Thanks amongst others to:
 *
 *     https://github.com/kokke/tiny-AES128-C  for code and ideas, public domain.
 */

// Core support/APIs.
#include "utility/OTAESGCM_OTAES128.h"
#include "utility/OTAESGCM_OTAESGCM.h"

// Implementations.
#include "utility/OTAESGCM_OTAES128Impls.h"


#endif
