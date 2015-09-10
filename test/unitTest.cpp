#include "unitTest.h"

void error(int expected, int actual, int line)
  {
  for( ; ; )
    {
    Serial.print(F("***Test FAILED*** expected=\t0x"));
    Serial.print(expected, HEX);
    Serial.print(F("actual=\t0x"));
    Serial.print(actual, HEX);
    if(0 != line)
      {
      Serial.print(F(" at line "));
      Serial.print(line);
      }
    Serial.println();
//    LED_HEATCALL_ON();
//    tinyPause();
//    LED_HEATCALL_OFF();
//    sleepLowPowerMs(1000);
    delay(1000);
    }
  }
  
/*void testLibVersion()
  {
  Serial.println("LibVersion");
  AssertIsEqual(0, ARDUINO_LIB_AESGCM_VERSION_MAJOR);
  AssertIsEqual(2, ARDUINO_LIB_AESGCM_VERSION_MINOR);
}*/
