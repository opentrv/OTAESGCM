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

/*Unit test routines for library code.
 */

// Include the library under test.
#include <OTAESGCM.h>
#include <avr/pgmspace.h>
#include "unitTest.h"

void setup()
  {
  // initialize serial communications at appropriate rate.
  Serial.begin(SERIAL_BAUD); 
  }

static const int AES_KEY_SIZE = 128; // in bits
static const int GCM_NONCE_LENGTH = 12; // in bytes
static const int GCM_TAG_LENGTH = 16; // in bytes (default 16, 12 possible)
  
/**
 * @brief  Test library version
 */
static void testLibVersion()
  {
  Serial.println("LibVersion");
  AssertIsEqual(0, ARDUINO_LIB_OTAESGCM_VERSION_MAJOR);
  AssertIsEqual(2, ARDUINO_LIB_OTAESGCM_VERSION_MINOR);
  }

//    /**Test on specific simple plaintext/ADATA.key value.
//     * Can be used to test MCU-based implementations.
//     */
//    @Test
//    public void testAESGCMAll0() throws Exception
//        {
//        final byte[] input = new byte[30]; // All-zeros input.
//
//        // All-zeros key.
//        final SecretKey key = new SecretKeySpec(new byte[AES_KEY_SIZE/8], 0, AES_KEY_SIZE/8, "AES");
//        final byte[] nonce = new byte[GCM_NONCE_LENGTH]; // All-zeros nonce.
//        final byte[] aad = new byte[4]; // All-zeros ADATA.
//
//        // Encrypt...
//        final Cipher cipherE = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE"); // JDK 7 breaks here..
//        final GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
//        cipherE.init(Cipher.ENCRYPT_MODE, key, spec);
//        cipherE.updateAAD(aad);
//        final byte[] cipherText = cipherE.doFinal(input);
//        assertEquals(input.length + GCM_TAG_LENGTH, cipherText.length);
//        System.out.println(DatatypeConverter.printHexBinary(cipherText));
//        assertEquals((16 == GCM_TAG_LENGTH) ?
//            "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948B614772C7929CD0DD681BD8A37A656F33" :
//            "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948B614772C7929CD0DD681BD8A3",
//            DatatypeConverter.printHexBinary(cipherText));
//
//        // Decrypt...
//        final Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE"); // JDK 7 breaks here..
//        cipherD.init(Cipher.DECRYPT_MODE, key, spec);
//        cipherD.updateAAD(aad);
//        final byte[] plainText = cipherD.doFinal(cipherText);
//        // Check that the decryption result matches.
//        assertTrue((Arrays.equals(input, plainText)));
//        }


// A const all-zeros block useful for keys, nonce, plaintext, etc.
static const uint8_t allZerosBlock[32] = { };

// Check that all zeros key, plaintext and ADATA gives the correct result.
static void testAESGCMAll0()
  {
  Serial.println("AESGCMAll0");
  // Inputs to encryption.
  const uint8_t inputSize = 30;
//  uint8_t input[30]; // All-zeros input, typical input size.
//  memset(input, 0x0, sizeof(input));
  const uint8_t *input = allZerosBlock;

//  uint8_t key[AES_KEY_SIZE/8];
//  memset(key, 0, sizeof(key)); // All-zeros key.
  const uint8_t *key = allZerosBlock;

//  uint8_t nonce[GCM_NONCE_LENGTH];
//  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  const uint8_t *nonce = allZerosBlock;

  const uint8_t aadSize = 4;
//  uint8_t aad[4];
//  memset(aad, 0, sizeof(aad)); // All-zeros ADATA.
  const uint8_t *aad = allZerosBlock;

  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  memset(tag, 0, sizeof(tag));
  uint8_t cipherText[max(32, inputSize)]; // Space for encrypted tex, rounded up to block size.
  memset(cipherText, 0, sizeof(cipherText));

  // Instance to perform enc/dec.
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  gen.gcmEncrypt(key, nonce, input, inputSize,
                         aad, aadSize, cipherText, tag);
  // Check some of the cipher text and tag.
//            "0388DACE60B6A392F328C2B971B2FE78 F795AAAB494B5923F7FD89FF948B  61 47 72 C7 92 9C D0 DD 68 1B D8 A3 7A 65 6F 33" :
  AssertIsEqual(0x03, cipherText[0]);
  AssertIsEqual(0x88, cipherText[1]);
  AssertIsEqual(0x8b, cipherText[29]);
  AssertIsEqual(0x61, tag[0]);
  AssertIsEqual(0x33, tag[15]);
  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(key, nonce,
                            cipherText, sizeof(cipherText),
                            aad, aadSize,
                            tag, plain));
  AssertIsEqual(0, memcmp(input, plain, inputSize)); // 0 indicates plain text recovered correctly.
  }


// Check that padding works
static void testAESGCMPadding()
  {
  Serial.println("AESGCMPadding");
  // Inputs to encryption.
  uint8_t input[9]; // All-zeros input
  memset(input, 0x55, sizeof(input));
  
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  uint8_t aad[4];
  memset(aad, 0, sizeof(aad)); // All-zeros ADATA.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(input)]; // Space for encrypted text
  memset(cipherText, 0, sizeof(cipherText));
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  gen.gcmEncrypt(key, nonce, input, sizeof(input),
                         aad, sizeof(aad), cipherText, tag);
  // Check some of the cipher text and tag. Generated from java cipher
//             0x56DD8F9B35E3F6C7A6 BDAF5DEC6047100A8233C7E36900C1D9
  AssertIsEqual(0x56, cipherText[0]);
  AssertIsEqual(0xdd, cipherText[1]);
  AssertIsEqual(0xa6, cipherText[sizeof(cipherText)-1]);
  AssertIsEqual(0xbd, tag[0]);
  AssertIsEqual(0xd9, tag[15]);
  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(  key, nonce,
                                cipherText, sizeof(cipherText),
                                aad, sizeof(aad),
                                tag, plain));
  AssertIsEqual(0, memcmp(input, plain, sizeof(input))); // 0 indicates plain text recovered correctly.
  }

// Check using NIST GCMVS test vector
  // keylen = 128, ivlen = 96, ptlen = 128, aadlen = 160, taglen = 128, count = 0
static void testGCMVS0()
  {
  Serial.println("GCMVS0");
  // Inputs to encryption.
  uint8_t input[16] = { 0x7b, 0x43, 0x01, 0x6a, 0x16, 0x89, 0x64, 0x97, 0xfb, 0x45, 0x7b, 0xe6, 0xd2, 0xa5, 0x41, 0x22 }; // All-zeros input, typical input size.
  
  uint8_t key[AES_KEY_SIZE/8] = { 0xd4, 0xa2, 0x24, 0x88, 0xf8, 0xdd, 0x1d, 0x5c, 0x6c, 0x19, 0xa7, 0xd6, 0xca, 0x17, 0x96, 0x4c };
  
  uint8_t nonce[GCM_NONCE_LENGTH] = { 0xf3, 0xd5, 0x83, 0x7f, 0x22, 0xac, 0x1a, 0x04, 0x25, 0xe0, 0xd1, 0xd5 };
  
  uint8_t aad[20] = { 0xf1, 0xc5, 0xd4, 0x24, 0xb8, 0x3f, 0x96, 0xc6, 0xad, 0x8c, 0xb2, 0x8c, 0xa0, 0xd2, 0x0e, 0x47, 0x5e, 0x02, 0x3b, 0x5a };
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(input)]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  gen.gcmEncrypt(key, nonce, input, sizeof(input),
                         aad, sizeof(aad), cipherText, tag);
  // Check some of the cipher text and tag.
//            "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948B  61 47 72 C7 92 9C D0 DD 68 1B D8 A3 7A 65 6F 33" :
  AssertIsEqual(0xc2, cipherText[0]);
  AssertIsEqual(0xbd, cipherText[1]);
  AssertIsEqual(0xa8, cipherText[sizeof(cipherText)-1]);
  AssertIsEqual(0xf2, tag[0]);
  AssertIsEqual(0x9c, tag[15]);

  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(  key, nonce,
                            cipherText, sizeof(cipherText),
                            aad, sizeof(aad),
                            tag, plain));
  AssertIsEqual(0, memcmp(input, plain, sizeof(input))); // 0 indicates plain text recovered correctly.
  }

  // keylen = 128, ivlen = 96, ptlen = 256, aadlen = 128, taglen = 128, count = 0
static void testGCMVS1()
  {
  Serial.println("GCMVS1");
  // Inputs to encryption.
  uint8_t input[32] = { 0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad, 0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01, 0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac, 0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01 }; // All-zeros input, typical input size.
  
  uint8_t key[AES_KEY_SIZE/8] = { 0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62, 0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc };
  
  uint8_t nonce[GCM_NONCE_LENGTH] = { 0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa, 0xe4, 0xed, 0x2f, 0x6d };
  
  uint8_t aad[16] = { 0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73, 0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1 };
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(input)]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  gen.gcmEncrypt(key, nonce, input, sizeof(input),
                                            aad, sizeof(aad), cipherText, tag);
  // Check some of the cipher text and tag.
//            "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948B  61 47 72 C7 92 9C D0 DD 68 1B D8 A3 7A 65 6F 33" :
  AssertIsEqual(0xdf, cipherText[0]);
  AssertIsEqual(0xce, cipherText[1]);
  AssertIsEqual(0xdb, cipherText[sizeof(cipherText)-1]);
  AssertIsEqual(0x54, tag[0]);
  AssertIsEqual(0xf2, tag[15]);

  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(  key, nonce,
                            cipherText, sizeof(cipherText),
                            aad, sizeof(aad),
                            tag, plain));
  AssertIsEqual(0, memcmp(input, plain, sizeof(input))); // 0 indicates plain text recovered correctly.
  }

// Check that authentication works correctly.
static void testAESGCMAuthentication()
  {
  Serial.println("AESGCMAuthentication");
  // Inputs to encryption.
  uint8_t input[32]; // All-zeros input, typical input size.
  memset(input, 0x0, sizeof(input));
  
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  uint8_t aad[4];
  memset(aad, 0, sizeof(aad)); // All-zeros ADATA.
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(input)]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  gen.gcmEncrypt(key, nonce, input, sizeof(input),
              aad, sizeof(aad), cipherText, tag);
  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  uint8_t tempTag[GCM_TAG_LENGTH];
  memcpy(tempTag, tag, GCM_TAG_LENGTH);

  // Un-hacked tag should match.
  AssertIsTrue(gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                                    aad, sizeof(aad), tempTag, plain));
  // Various manglings of the tag should fail.
  tempTag[0]++;
  AssertIsTrue(!gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                                    aad, sizeof(aad), tempTag, plain));
  tempTag[0]--;

  tempTag[1]++;
  AssertIsTrue(!gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                                    aad, sizeof(aad), tempTag, plain));
  tempTag[1]--;

  tempTag[15]++;
  AssertIsTrue(!gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                                    aad, sizeof(aad), tempTag, plain));
  }

// Check that throws error on no data input
static void testAESGCMNoData()
  {
  Serial.println("AESGCMNoData");
  // Inputs to encryption.
  uint8_t plainText[16]; // Space for encrypted text.
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(plainText)]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  AssertIsEqual(0, gen.gcmEncrypt(key, nonce, NULL, 0,
                      NULL, 0, cipherText, tag));
  // Decrypt...
  uint8_t tempTag[GCM_TAG_LENGTH];
  memcpy(tempTag, tag, GCM_TAG_LENGTH);

  // No input data should return false.
  AssertIsTrue(!gen.gcmDecrypt(key, nonce, NULL, 0,
                      NULL, 0, tempTag, plainText));
  }

// Check that runs correctly with ADATA only
static void testAESGCMadataOnly()
  {
  Serial.println("AESGCMadataOnly");
  // Inputs to encryption.
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t ADATA[16];
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  AssertIsTrue(gen.gcmEncrypt(key, nonce, NULL, 0,
                      ADATA, sizeof(ADATA), NULL, tag));
  // Decrypt...
  uint8_t tempTag[GCM_TAG_LENGTH];
  memcpy(tempTag, tag, GCM_TAG_LENGTH);

  // Un-hacked tag should match.
  AssertIsTrue(gen.gcmDecrypt(key, nonce, NULL, 0,
                      ADATA, sizeof(ADATA), tempTag, NULL));
  }

// Check that throws error on no data input
static void testAESGCMcdataOnly()
  {
  Serial.println("AESGCMcdataOnly");
  // Inputs to encryption.
  uint8_t plainText[16]; // Space for encrypted text.
  memset(plainText, 0, sizeof(plainText));
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[sizeof(plainText)]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  AssertIsTrue(gen.gcmEncrypt(key, nonce, plainText, sizeof(plainText),
                      NULL, 0, cipherText, tag));
  // Decrypt...
  uint8_t tempTag[GCM_TAG_LENGTH];
  memcpy(tempTag, tag, GCM_TAG_LENGTH);

  // Un-hacked tag should match.
  AssertIsTrue(gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                      NULL, 0, tempTag, plainText));
  }

// Check that runs correctly with ADATA only
static void testAESGCMNoKey()
  {
  Serial.println("AESGCMNoKey");
  // Inputs to encryption.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t ADATA[16];
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  AssertIsTrue(!gen.gcmEncrypt(NULL, nonce, NULL, 0,
                      ADATA, sizeof(ADATA), NULL, tag));
  }

  // Check that runs correctly with ADATA only
static void testAESGCMNoIV()
  {
  Serial.println("AESGCMNoIV");
  // Inputs to encryption.
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t ADATA[16];
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGeneric<> gen;
  AssertIsTrue(!gen.gcmEncrypt(key, NULL, NULL, 0,
                      ADATA, sizeof(ADATA), NULL, tag));
  }
  
// To be called from loop() instead of main code when running unit tests.
// Tests generally flag an error and stop the test cycle with a call to panic() or error().
void loop()
  {
  static int loopCount = 0;

  // Allow the terminal console to be brought up.
  for(int i = 3; i > 0; --i)
    {
    Serial.print(F("Tests starting... "));
    Serial.print(i);
    Serial.println();
    delay(1000);
    }
  Serial.println();


  // Run the tests, fastest / newest / most-fragile / most-interesting first...
  testLibVersion();

  //testAESGCMNoKey();   // not currently implemented
  //testAESGCMNoIV();    // not currently implemented
  
  testAESGCMPadding();
  
  testAESGCMNoData();

  testAESGCMadataOnly();

  testAESGCMcdataOnly();
  
  testAESGCMAll0();

  testAESGCMAuthentication();

  testGCMVS0();

  testGCMVS1();

  // Announce successful loop completion and count.
  ++loopCount;
  Serial.println();
  Serial.print(F("%%% All tests completed OK, round "));
  Serial.print(loopCount);
  Serial.println();
  Serial.println();
  Serial.println();
  delay(2000);
  }
