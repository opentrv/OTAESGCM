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

Author(s) / Copyright (s): Damon Hart-Davis 2016
*/

/*
 * Driver and sanity test for portable C++ unit tests for this library.
 */

#include <stdint.h>
#include <gtest/gtest.h>
#include <OTAESGCM.h>


// Sanity test.
TEST(SanityTest,SelfTest)
{
    EXPECT_EQ(42, 42);
//    fputs("*** Tests built: " __DATE__ " " __TIME__ "\n", stderr);
}


/**
 * @brief   Getting started with the gtest libraries.
 * @note    - Add the following to Project>Properties>C/C++ Build>Settings>GCC G++ linker>Libraries (-l):
 *              - gtest
 *              - gtest_main
 *              - pthread
 *          - Select Google Testing in Run>Run Configuration>C/C++ Unit Test>testTest>C/C++ Testing and click Apply then Run
 *          - Saved the test config
 */

 /**
  * See also: https://github.com/google/googletest/blob/master/googletest/docs/Primer.md
  */
