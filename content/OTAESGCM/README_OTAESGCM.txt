Target platform: Arduino UNO (or similar)
Library format: pre-1.5-IDE AVR-only

Description
===========

The 'OTAESGCM' OpenTRV IoT-/Microcontroller- friendly, permissively licensed, AES-GCM implementation as Arduino library.
.

Uses as namespace to help reduce chance of name collisions.


Licence
=======

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

Author(s) / Copyright (s): Damon Hart-Davis 2015--2017
                           Deniz Erbilgin 2017



Notes
=====

Misfeatures to guard against:

  * Any received data, malformed in any way including by length,
    can cause a crash, eg non-block-sized data for decode.
    (Such bad data should be quickly and safely rejected.)
  
  * There should be no timing or power differences dependent on key or data
    during encode or decode.

  * APIs must be clear so that programmers know eg where padding must be supplied
    and for example even if inputs don't need padding, do output buffers?
  
  * Non-block-sized data is not supported. All input buffers must be multiples of 128 bits.


