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
                           Damon Hart-Davis 2015
*/

#ifndef OT_UNIT_TEST_H_
#define OT_UNIT_TEST_H_

#include <Arduino.h>
#include <OTV0p2Base.h> // necessary?

// Test expression and bucket out with error if false, else continue, including line number.
// Macros allow __LINE__ to work correctly.
#define AssertIsTrueWithErr(x, err) { if(!(x)) { unitTest.error(0, (err), __LINE__); } }
#define AssertIsTrue(x) AssertIsTrueWithErr((x), 0x0)
#define AssertIsEqual(expected, x) { unitTest.errorIfNotEqual((expected), (x), __LINE__); }
#define AssertIsEqualWithDelta(expected, x, delta) { unitTest.errorIfNotEqual((expected), (x), (delta), __LINE__); }

class OTUnitTest
{
public:
	OTUnitTest();

	void testLibVersion();


//private:
	/**
	 * @brief	Report an error from a unit test on Serial, and repeat so that it is not missed.
	 * @param	expected	expected value
	 * @param	actual		actual value
	 * @param	line		line error occurred at
	 */
	void error(int expected, int actual, int line);

	/**
	 * @brief	Common equality test
	 * @param	expected	expected value
	 * @param	actual		actual value
	 * @param	line		line error occurred at
	 */
	inline void errorIfNotEqual(int expected, int actual, int line) { if(expected != actual) { error(expected, actual, line); } };	// TODO may be inlined
	/**
	 * @brief	Common equality tests
	 * @param	expected	expected value
	 * @param	actual		actual value
	 * @param	delta		maximum acceptable deviation of actual from expected
	 * @param	line		line error occurred at
	 */
	inline void errorIfNotEqual(int expected, int actual, int delta, int line) { if(abs(expected - actual) > delta) { error(expected, actual, line); } }

};

extern OTUnitTest unitTest;


#if F_CPU == 1000000 // 1MHz CPU indicates V0p2 board with 4800 baud serial link.
#define ON_V0P2_BOARD
#define SERIAL_BAUD 4800
#else
#define SERIAL_BAUD 9600
#endif



#endif  // OT_UNIT_TEST_H_
