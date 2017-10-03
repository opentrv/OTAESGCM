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
  AssertIsEqual(1, ARDUINO_LIB_OTAESGCM_VERSION_MAJOR);
  AssertIsEqual(0, ARDUINO_LIB_OTAESGCM_VERSION_MINOR);
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

namespace W0
{
    // Workspace for AES functions
    static constexpr size_t workspaceRequired = OTAESGCM::OTAES128GCMGenericWithWorkspace<>::workspaceRequired;
    static uint8_t workspace[workspaceRequired];

    // A const all-zeros block useful for keys, nonce, plaintext, etc.
    static const uint8_t allZerosBlock[32] = { };
    static uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
    static const uint8_t inputSize = 30; // Typical non-block-size input size.
    static uint8_t cipherText[max(32, inputSize)]; // Space for encrypted text, rounded up to block size.
    static uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.

    void resetFields()
    {
        memset(workspace, 0, sizeof(workspace));
        memset(tag, 0, sizeof(tag));
        memset(cipherText, 0, sizeof(cipherText));
        memset(plain, 0, sizeof(plain));
    }
}

// Check that all zeros key, plaintext and ADATA gives the correct result.
static void testAESGCMAll0()
  {
  Serial.println("AESGCMAll0");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
//  uint8_t input[30]; // All-zeros input.
//  memset(input, 0x0, sizeof(input));
  const uint8_t *input = W0::allZerosBlock;

//  uint8_t key[AES_KEY_SIZE/8];
//  memset(key, 0, sizeof(key)); // All-zeros key.
  const uint8_t *key = W0::allZerosBlock;

//  uint8_t nonce[GCM_NONCE_LENGTH];
//  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  const uint8_t *nonce = W0::allZerosBlock;

  const uint8_t aadSize = 4;
//  uint8_t aad[4];
//  memset(aad, 0, sizeof(aad)); // All-zeros ADATA.
  const uint8_t *aad = W0::allZerosBlock;

  // Space for outputs from encryption.
  memset(W0::tag, 0, sizeof(W0::tag));
  memset(W0::cipherText, 0, sizeof(W0::cipherText));

  // Instance to perform enc/dec.
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(W0::workspace, sizeof(W0::workspace));
  gen.gcmEncryptPadded(key, nonce, input, W0::inputSize,
                         aad, aadSize, W0::cipherText, W0::tag);
  // Check some of the cipher text and tag.
//            "0388DACE60B6A392F328C2B971B2FE78 F795AAAB494B5923F7FD89FF948B  61 47 72 C7 92 9C D0 DD 68 1B D8 A3 7A 65 6F 33" :
  AssertIsEqual(0x03, W0::cipherText[0]);
  AssertIsEqual(0x88, W0::cipherText[1]);
  AssertIsEqual(0x8b, W0::cipherText[29]);
  AssertIsEqual(0xb6, W0::tag[0]); // Was, before CDATAlength fix, AssertIsEqual(0x61, tag[0]);
  AssertIsEqual(0x18, W0::tag[15]); // Was, before CDATAlength fix, AssertIsEqual(0x33, tag[15]);
  // Decrypt...
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(key, nonce,
          W0::cipherText, sizeof(W0::cipherText),
                            aad, aadSize,
                            W0::tag, W0::plain));
  AssertIsEqual(0, memcmp(input, W0::plain, W0::inputSize)); // 0 indicates plain text recovered correctly.
  }

#if 0
// Check that padding works
static void testAESGCMPadding()
  {
  Serial.println("AESGCMPadding");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  constexpr uint8_t inputSize = 9;
  memset(W0::input, 0x55, inputSize);
  
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  uint8_t aad[4];
  memset(aad, 0, sizeof(aad)); // All-zeros ADATA.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(16, inputSize)]; // Space for encrypted text
  memset(cipherText, 0, sizeof(cipherText));
  
  // Instance to perform enc/dec.
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  gen.gcmEncryptPadded(key, nonce, input, inputSize,
                         aad, sizeof(aad), cipherText, tag);
  // Check some of the cipher text and tag. Generated from java cipher
//             0x56DD8F9B35E3F6C7A6 BDAF5DEC6047100A8233C7E36900C1D9
  AssertIsEqual(0x56, cipherText[0]);
  AssertIsEqual(0xdd, cipherText[1]);
//  AssertIsEqual(0xa6, cipherText[sizeof(cipherText)-1]);
  AssertIsEqual(0xa6, cipherText[8]);
  AssertIsEqual(0x9b, tag[0]); // Was, before CDATAlength fix, AssertIsEqual(0xbd, tag[0]);
  AssertIsEqual(0x75, tag[15]); // Was, before CDATAlength fix, AssertIsEqual(0xd9, tag[15]);
  // Decrypt...
  uint8_t plain[sizeof(cipherText)]; // Space for decrypted text.
  // Should pass authentication and produce the original plaintext.
  AssertIsTrue(gen.gcmDecrypt(  key, nonce,
                                cipherText, sizeof(cipherText),
                                aad, sizeof(aad),
                                tag, plain));
  AssertIsEqual(0, memcmp(input, plain, sizeof(input))); // 0 indicates plain text recovered correctly.
  }

// Check using NIST GCMVS test vector.
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmvs.pdf
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
//
//[Keylen = 128]
//[IVlen = 96]
//[PTlen = 128]
//[AADlen = 160]
//[Taglen = 128]
//
//Count = 0
//Key = d4a22488f8dd1d5c6c19a7d6ca17964c
//IV = f3d5837f22ac1a0425e0d1d5
//PT = 7b43016a16896497fb457be6d2a54122
//AAD = f1c5d424b83f96c6ad8cb28ca0d20e475e023b5a
//CT = c2bd67eef5e95cac27e3b06e3031d0a8
//Tag = f23eacf9d1cdf8737726c58648826e9c
//
// keylen = 128, ivlen = 96, ptlen = 128, aadlen = 160, taglen = 128, count = 0
static void testGCMVS0()
  {
  Serial.println("GCMVS0");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  static const uint8_t input[16] = { 0x7b, 0x43, 0x01, 0x6a, 0x16, 0x89, 0x64, 0x97, 0xfb, 0x45, 0x7b, 0xe6, 0xd2, 0xa5, 0x41, 0x22 };
  static const uint8_t key[AES_KEY_SIZE/8] = { 0xd4, 0xa2, 0x24, 0x88, 0xf8, 0xdd, 0x1d, 0x5c, 0x6c, 0x19, 0xa7, 0xd6, 0xca, 0x17, 0x96, 0x4c };
  static const uint8_t nonce[GCM_NONCE_LENGTH] = { 0xf3, 0xd5, 0x83, 0x7f, 0x22, 0xac, 0x1a, 0x04, 0x25, 0xe0, 0xd1, 0xd5 };
  static const uint8_t aad[20] = { 0xf1, 0xc5, 0xd4, 0x24, 0xb8, 0x3f, 0x96, 0xc6, 0xad, 0x8c, 0xb2, 0x8c, 0xa0, 0xd2, 0x0e, 0x47, 0x5e, 0x02, 0x3b, 0x5a };
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(16, sizeof(input))]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  gen.gcmEncryptPadded(key, nonce, input, sizeof(input),
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

// Check using NIST GCMVS test vector.
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmvs.pdf
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
//
//[Keylen = 128]
//[IVlen = 96]
//[PTlen = 256]
//[AADlen = 128]
//[Taglen = 128]
//
//Count = 0
//Key = 298efa1ccf29cf62ae6824bfc19557fc
//IV = 6f58a93fe1d207fae4ed2f6d
//PT = cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901
//AAD = 021fafd238463973ffe80256e5b1c6b1
//CT = dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db
//Tag = 542465ef599316f73a7a560509a2d9f2
//
// keylen = 128, ivlen = 96, ptlen = 256, aadlen = 128, taglen = 128, count = 0
static void testGCMVS1()
  {
  Serial.println("GCMVS1");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  static const uint8_t input[32] = { 0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad, 0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01, 0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac, 0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01 };
  static const uint8_t key[AES_KEY_SIZE/8] = { 0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62, 0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc };
  static const uint8_t nonce[GCM_NONCE_LENGTH] = { 0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa, 0xe4, 0xed, 0x2f, 0x6d };
  static const uint8_t aad[16] = { 0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73, 0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1 };
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(32, sizeof(input))]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  gen.gcmEncryptPadded(key, nonce, input, sizeof(input),
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

// Check using NIST GCMVS test vector.
// Test via fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_STATELESS interface.
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmvs.pdf
// See http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
//
//[Keylen = 128]
//[IVlen = 96]
//[PTlen = 256]
//[AADlen = 128]
//[Taglen = 128]
//
//Count = 0
//Key = 298efa1ccf29cf62ae6824bfc19557fc
//IV = 6f58a93fe1d207fae4ed2f6d
//PT = cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901
//AAD = 021fafd238463973ffe80256e5b1c6b1
//CT = dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db
//Tag = 542465ef599316f73a7a560509a2d9f2
//
// keylen = 128, ivlen = 96, ptlen = 256, aadlen = 128, taglen = 128, count = 0
static void testGCMVS1ViaFixed32BTextSize()
  {
  Serial.println("GCMVS1ViaFixed32BTextSize");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  static const uint8_t input[32] = { 0xcc, 0x38, 0xbc, 0xcd, 0x6b, 0xc5, 0x36, 0xad, 0x91, 0x9b, 0x13, 0x95, 0xf5, 0xd6, 0x38, 0x01, 0xf9, 0x9f, 0x80, 0x68, 0xd6, 0x5c, 0xa5, 0xac, 0x63, 0x87, 0x2d, 0xaf, 0x16, 0xb9, 0x39, 0x01 };
  static const uint8_t key[AES_KEY_SIZE/8] = { 0x29, 0x8e, 0xfa, 0x1c, 0xcf, 0x29, 0xcf, 0x62, 0xae, 0x68, 0x24, 0xbf, 0xc1, 0x95, 0x57, 0xfc };
  static const uint8_t nonce[GCM_NONCE_LENGTH] = { 0x6f, 0x58, 0xa9, 0x3f, 0xe1, 0xd2, 0x07, 0xfa, 0xe4, 0xed, 0x2f, 0x6d };
  static const uint8_t aad[16] = { 0x02, 0x1f, 0xaf, 0xd2, 0x38, 0x46, 0x39, 0x73, 0xff, 0xe8, 0x02, 0x56, 0xe5, 0xb1, 0xc6, 0xb1 };
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(32, sizeof(input))]; // Space for encrypted text.
  // Do encryption via simplified interface.
  AssertIsTrue(OTAESGCM::fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_WITH_LWORKSPACE(
            workspace, workspaceRequired,
            key, nonce,
            aad, sizeof(aad),
            input,
            cipherText, tag));
  // Check some of the cipher text and tag.
//            "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948B  61 47 72 C7 92 9C D0 DD 68 1B D8 A3 7A 65 6F 33" :
  AssertIsEqual(0xdf, cipherText[0]);
  AssertIsEqual(0x91, cipherText[5]);
  AssertIsEqual(0xdb, cipherText[sizeof(cipherText)-1]);
  AssertIsEqual(0x24, tag[1]);
  AssertIsEqual(0xd9, tag[14]);
  // Decrypt via simplified interface...
  uint8_t inputDecoded[32];
  AssertIsTrue(OTAESGCM::fixed32BTextSize12BNonce16BTagSimpleDec_DEFAULT_WITH_LWORKSPACE(
            workspace, workspaceRequired,
            key, nonce,
            aad, sizeof(aad),
            cipherText, tag,
            inputDecoded));
  AssertIsEqual(0, memcmp(input, inputDecoded, 32));
  // Try enc/auth with no (ie zero-length) plaintext.
  AssertIsTrue(OTAESGCM::fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_WITH_LWORKSPACE(
            workspace, workspaceRequired,
            key, nonce,
            aad, sizeof(aad),
            NULL,
            cipherText, tag));
  // Check some of the tag.
//  AssertIsEqual(0x24, tag[1]);
//  AssertIsEqual(0xd9, tag[14]);
  // Auth/decrypt (auth should still succeed).
  AssertIsTrue(OTAESGCM::fixed32BTextSize12BNonce16BTagSimpleDec_DEFAULT_WITH_LWORKSPACE(
            workspace, workspaceRequired,
            key, nonce,
            aad, sizeof(aad),
            NULL, tag,
            inputDecoded));  
  }



// Check that authentication works correctly.
static void testAESGCMAuthentication()
  {
  Serial.println("AESGCMAuthentication");

  // First clear any data from other tests.
  W0::resetFields();
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
  uint8_t cipherText[max(32, sizeof(input))]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  gen.gcmEncryptPadded(key, nonce, input, sizeof(input),
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

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  uint8_t plainText[16]; // Space for encrypted text.
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(16, sizeof(plainText))]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  AssertIsEqual(0, gen.gcmEncryptPadded(key, nonce, NULL, 0,
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

  // First clear any data from other tests.
  W0::resetFields();
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
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  AssertIsTrue(gen.gcmEncryptPadded(key, nonce, NULL, 0,
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

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  uint8_t plainText[16]; // Space for encrypted text.
  memset(plainText, 0, sizeof(plainText));
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t cipherText[max(16, sizeof(plainText))]; // Space for encrypted text.
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  AssertIsTrue(gen.gcmEncryptPadded(key, nonce, plainText, sizeof(plainText),
                      NULL, 0, cipherText, tag));
  // Decrypt...
  uint8_t tempTag[GCM_TAG_LENGTH];
  memcpy(tempTag, tag, GCM_TAG_LENGTH);

  // Un-hacked tag should match.
  AssertIsTrue(gen.gcmDecrypt(key, nonce, cipherText, sizeof(cipherText),
                      NULL, 0, tempTag, plainText));
  }

#if 0 // was not included for whatever reason
// Check that runs correctly with ADATA only
static void testAESGCMNoKey()
  {
  Serial.println("AESGCMNoKey");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  
  uint8_t nonce[GCM_NONCE_LENGTH];
  memset(nonce, 0x0, sizeof(nonce)); // All-zeros nonce.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t ADATA[16];
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  AssertIsTrue(!gen.gcmEncryptPadded(NULL, nonce, NULL, 0,
                      ADATA, sizeof(ADATA), NULL, tag));
  }

  // Check that runs correctly with ADATA only
static void testAESGCMNoIV()
  {
  Serial.println("AESGCMNoIV");

  // First clear any data from other tests.
  W0::resetFields();
  // Inputs to encryption.
  uint8_t key[AES_KEY_SIZE/8];
  memset(key, 0, sizeof(key)); // All-zeros key.
  
  // Space for outputs from encryption.
  uint8_t tag[GCM_TAG_LENGTH]; // Space for tag.
  uint8_t ADATA[16];
  
  // Instance to perform enc/dec.
  //OpenTRV::AESGCM::AES128GCM16small eo;
  // Do encryption.
  OTAESGCM::OTAES128GCMGenericWithWorkspace<> gen(workspace, sizeof(workspace));
  AssertIsTrue(!gen.gcmEncryptPadded(key, NULL, NULL, 0,
                      ADATA, sizeof(ADATA), NULL, tag));
  }
#endif
#endif

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
  
//  testAESGCMPadding();
  testAESGCMAll0();

//  testAESGCMNoData();
//  testAESGCMadataOnly();
//  testAESGCMcdataOnly();
//  testAESGCMAuthentication();
//  testGCMVS0();
//  testGCMVS1();
//  testGCMVS1ViaFixed32BTextSize();

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
