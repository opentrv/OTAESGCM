/**
 * 
 *
 */

#ifndef UNIT_TEST_H_
#define UNIT_TEST_H_

#include <Arduino.h>

void error(int expected, int actual, int line);

// Deal with common equality test.
inline void errorIfNotEqual(int expected, int actual, int line) { if(expected != actual) { error(expected, actual, line); } }
// Allowing a delta.
inline void errorIfNotEqual(int expected, int actual, int delta, int line) { if(abs(expected - actual) > delta) { error(expected, actual, line); } }

// Test expression and bucket out with error if false, else continue, including line number.
// Macros allow __LINE__ to work correctly.
#define AssertIsTrueWithErr(x, err) { if(!(x)) { error(0, (err), __LINE__); } }
#define AssertIsTrue(x) AssertIsTrueWithErr((x), 0)
#define AssertIsEqual(expected, x) { errorIfNotEqual((expected), (x), __LINE__); }
#define AssertIsEqualWithDelta(expected, x, delta) { errorIfNotEqual((expected), (x), (delta), __LINE__); }

void testLibVersion();



#if F_CPU == 1000000 // 1MHz CPU indicates V0p2 board with 4800 baud serial link.
#define ON_V0P2_BOARD
#define SERIAL_BAUD 4800
#else
#define SERIAL_BAUD 9600
#endif



#endif  // UNIT_TEST_H_
