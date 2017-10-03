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

Author(s) / Copyright (s): Deniz Erbilgin 2015--2017
                           Damon Hart-Davis 2015--2017
*/

/* OpenTRV OTAESGCM microcontroller-/IoT- friendly AES(128)-GCM implementation. */

#ifndef ARDUINO_LIB_OTAESGCM_OTAESGCM_H
#define ARDUINO_LIB_OTAESGCM_OTAESGCM_H

#include <stddef.h>
#include <stdint.h>

// Get available AES API and cipher implementations.
#include "OTAESGCM_OTAES128.h"
#include "OTAESGCM_OTAES128Impls.h"

#undef OTAESGCM_ALLOW_UNPADDED
#undef OTAESGCM_ALLOW_NON_WORKSPACE

// Use namespaces to help avoid collisions.
namespace OTAESGCM
    {

static constexpr uint8_t AES128GCM_BLOCK_SIZE = 16; // GCM block size in bytes. This must be the same as the AES block size.
static constexpr uint8_t AES128GCM_IV_SIZE    = 12; // GCM initialisation size in bytes.
static constexpr uint8_t AES128GCM_TAG_SIZE   = 16; // GCM authentication tag size in bytes.


    // Base class / interface for AES128-GCM encryption/decryption.
    // Neither re-entrant nor ISR-safe except where stated.
    class OTAES128GCM
        {
        protected:
            // Only derived classes can construct an instance.
            constexpr OTAES128GCM() { }

        public:
#if defined(OTAESGCM_ALLOW_UNPADDED)
            /**
             * @brief   performs AES-GCM encryption.
             * 			If ADATA unused, set ADATA to NULL and ADATALength to 0.
             * 			If PDATA unused (this is GMAC),
             * 			the set PDATA and CDATA to NULL and PDATALength to 0.
             * @todo	Make GMAC helper function.
             * @param   key		pointer to 16 byte (128 bit) key; never NULL
             * @param   IV             	pointer to 12 byte (96 bit) IV;
             *                          never NULL
             * @param   PDATA          	pointer to plaintext input array,
             *                          this is internally padded up to
             *                          a multiple of the blocksize;
             *                          NULL if length 0.
             * @param   PDATALength	length of plaintext array in bytes,
             *                          can be zero,
             *                          need not be blocksize multiple.
             * @param   ADATA           pointer to additional input data array;
             *                          NULL if length 0.
             * @param   ADATALength    	length of additional data in bytes,
             *                          can be zero
             * @param   CDATA           buffer to output ciphertext to,
             *                          size MUST BE PADDED/EXPANDED TO FULL
             *                          BLOCKSIZE MULTIPLE at/above PDATAlength;
             *                          (nominally set to NULL if PDATA is NUL
             *                          but seems to cause a crash)
             * @param   tag             pointer to 16 byte tag output buffer;
             *                          never NULL
             * @retval	true if encryption is successful, else false
             */
            virtual bool gcmEncrypt(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATA, uint8_t PDATALength,
                const uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag) = 0;
            /**
             * @brief   performs AES-GCM encryption on padded data.
             *          If ADATA unused, set ADATA to NULL and ADATALength to 0.
             *          If PDATA unused (this is GMAC),
             *          then set PDATA and CDATA to NULL and PDATALength to 0.
             * @todo    Make GMAC helper function.
             * @param   key     pointer to 16 byte (128 bit) key; never NULL
             * @param   IV              pointer to 12 byte (96 bit) IV;
             *                          never NULL
             * @param   PDATAPaddded    pointer to plaintext input array,
             *                          MUST BT a multiple of the blocksize;
             *                          NULL if length 0.
             * @param   PDATALength     length of plaintext array in bytes,
             *                          can be zero,
             *                          MUST BE blocksize multiple.
             * @param   ADATA           pointer to additional input data array;
             *                          NULL if length 0.
             * @param   ADATALength     length of additional data in bytes,
             *                          can be zero
             * @param   CDATA           buffer to output ciphertext to,
             *                          size MUST BE PADDED/EXPANDED TO FULL
             *                          BLOCKSIZE MULTIPLE at/above PDATAlength;
             *                          (nominally set to NULL if PDATA is NULL
             *                          but seems to cause a crash)
             * @param   tag             pointer to 16 byte tag output buffer;
             *                          never NULL
             * @retval  true if encryption is successful, else false
             *
             * Plain-text must be an exact multiple of block length, eg padded.
             * This version may be smaller and faster and need less stack
             * if separately implemented, else default to generic gcmEncrypt().
             */
            virtual bool gcmEncryptPadded(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATAPadded, uint8_t PDATALength,
                const uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag)
                { return(gcmEncrypt(key, IV, PDATAPadded, PDATALength, ADATA, ADATALength, CDATA, tag)); }
#else
            virtual bool gcmEncryptPadded(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATAPadded, uint8_t PDATALength,
                const uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag) = 0;
#endif
            /**
             * @brief   performs AES-GCM decryption and authentication
             * @param    key             pointer to 16 byte (128 bit) key
             * @param    IV              pointer to 12 byte (96 bit) IV
             * @param    CDATA           pointer to ciphertext array
             * @param    CDATALength     length of ciphertext array
             * @param    ADATA           pointer to additional data array
             * @param    ADATALength     length of additional data
             * @param    PDATA           buffer to output plaintext to;
             *                           must be same length as CDATA
             * @retval   true if decryption and authentication successful,
             *           else false
             */
            virtual bool gcmDecrypt(
                 const uint8_t* key, const uint8_t* IV,
                 const uint8_t* CDATA, uint8_t CDATALength,
                 const uint8_t* ADATA, uint8_t ADATALength,
                 const uint8_t* messageTag, uint8_t *PDATA) = 0;

#if 0 // Defining the virtual destructor uses ~800+ bytes of Flash by forcing use of malloc()/free().
            // Ensure safe instance destruction when derived from.
            // by default attempts to shut down the sensor and otherwise free resources when done.
            // This uses ~800+ bytes of Flash by forcing use of malloc()/free().
            virtual ~OTAES128GCM() { }
#else
#define OTAES128GCM_NO_VIRT_DEST // Beware, no virtual destructor so be careful of use via base pointers.
#endif
        };

    // Workspaces for OTAES128GCMGenericBase functions.
    // Having the large byte arrays broken out explicitly
    // rather than allocated from the stack
    // allows more visibility and (potentially) control.
    namespace GGBWS
    {
        /**
         * @struct  Bulk of GHASH() workspace.
         * @note    32 bytes for AES128.
         * */
        struct GHASHWorkspace final
        {
            uint8_t ghashTmp[AES128GCM_BLOCK_SIZE]; // If using full blocks, no need for tmp.
            uint8_t gFieldMultiplyTmp[AES128GCM_BLOCK_SIZE]; // If using full blocks, no need for tmp.
        };

        /**
         * @struct  Bulk of GCTR() workspace.
         * @note    32 bytes for AES128.
         * */
        struct GCTRWorkspace final
        {
            uint8_t ctrBlock[AES128GCM_BLOCK_SIZE];
            uint8_t tmp[AES128GCM_BLOCK_SIZE]; // If using full blocks, no need for tmp.
        };

        /**
         * @struct  Bulk of GCTRPadded() workspace.
         * @note    16 bytes for AES128.
         * */
        struct GCTRPaddedWorkspace final
        {
            uint8_t ctrBlock[AES128GCM_BLOCK_SIZE];
        };

        /**
         * @struct  Bulk of generateCDATA() workspace.
         * @note    48 = 16 + 32 bytes.
         */
        struct GenCDATAWorkspace final
        {
            uint8_t ctrBlock[AES128GCM_BLOCK_SIZE];
            GCTRWorkspace gctrSpace;
        };
        /**
         * @struct  Bulk of generateCDATAPadded() workspace.
         * @note    32 = 16 + 16 bytes.
         */
        struct GenCDATAPaddedWorkspace final
        {
            uint8_t ctrBlock[AES128GCM_BLOCK_SIZE];
            GCTRPaddedWorkspace gctrSpace;
        };
        /**
         * @struct  Bulk of generateTag() workspace.
         * @note    64 = 16 + 32 + 16 bytes.
         */
        struct GenerateTagWorkspace final
        {
            uint8_t S[AES128GCM_BLOCK_SIZE];
            GHASHWorkspace ghashSpace;
            // lengthBuffer and gctrSpace are/contain 16 byte uint8_t arrays
            // and are not used simultaneously.
            union
            {
                uint8_t lengthBuffer[16];
                GCTRPaddedWorkspace gctrSpace;
            };
        };
        /**
         * @struct  Bulk of gcmEncrypt() workspace
         * @note    96 = 16 + 16 + 64 bytes.
         */
        struct GCMEncryptWorkspace final
        {
            uint8_t authKey[AES128GCM_BLOCK_SIZE];
            uint8_t ICB[AES128GCM_BLOCK_SIZE];
            // generateCDATA and generateTag are called separately
            // and so their workspaces can be a union.
            union {
                GenCDATAWorkspace cdataWorkspace;
                GenerateTagWorkspace tagWorkspace;
            };
        };
        /**
         * @struct  Bulk of generateCDATA() workspace
         * @note    96 = 16 + 16 + 64 bytes.
         */
        struct GCMEncryptPaddedWorkspace final
        {
            uint8_t authKey[AES128GCM_BLOCK_SIZE];
            uint8_t ICB[AES128GCM_BLOCK_SIZE];
            // generateCDATA and generateTag are called separately
            // and so their workspaces can be a union.
            union {
                GenCDATAPaddedWorkspace cdataWorkspace;
                GenerateTagWorkspace tagWorkspace;
            };
        };
        /**
         * @struct  Bulk of generateCDATA() workspace
         * @note    112 = 16 + 16 + 16 + 64 bytes.
         */
        struct GCMDecryptWorkspace final
        {
            uint8_t authKey[AES128GCM_BLOCK_SIZE];
            uint8_t ICB[AES128GCM_BLOCK_SIZE];
            uint8_t calculatedTag[AES128GCM_TAG_SIZE];
            // generateCDATA and generateTag are called separately
            // and so their workspaces can be a union.
            union {
                GenCDATAPaddedWorkspace cdataWorkspace;
                GenerateTagWorkspace tagWorkspace;
            };
        };

        // Workspace required for OTAES128GCMGenericBase functions.
        // All expected to be < 256.
        constexpr static uint8_t gcmEncryptWorkspaceRequired = sizeof(GGBWS::GCMEncryptWorkspace);
        constexpr static uint8_t gcmEncryptPaddedWorkspaceRequired = sizeof(GGBWS::GCMEncryptPaddedWorkspace);
        constexpr static uint8_t gcmDecryptWorkspaceRequired = sizeof(GGBWS::GCMDecryptWorkspace);

        // Compute the minimum and maximum workspace sizes
        // required or the GCM functions (excluding the underlying AES).
        constexpr static uint8_t minEncWS =
            (gcmEncryptWorkspaceRequired < gcmEncryptPaddedWorkspaceRequired) ? gcmEncryptWorkspaceRequired : gcmEncryptPaddedWorkspaceRequired;
        constexpr static uint8_t minWS =
            (minEncWS < gcmDecryptWorkspaceRequired) ? minEncWS : gcmDecryptWorkspaceRequired;
        constexpr static uint8_t maxEncWS =
            (gcmEncryptWorkspaceRequired > gcmEncryptPaddedWorkspaceRequired) ? gcmEncryptWorkspaceRequired : gcmEncryptPaddedWorkspaceRequired;
        constexpr static uint8_t maxWS =
            (maxEncWS > gcmDecryptWorkspaceRequired) ? maxEncWS : gcmDecryptWorkspaceRequired;
    }

    // Generic implementation, parameterised with type of underlying AES implementation.
    // The default AES implementation for the architecture is used unless otherwise specified.
    // This implementation is not specialised for a particular CPU/MCU for example.
    // This implementation carries no state beyond that of the AES128 implementation.
    class OTAES128GCMGenericBase : public OTAES128GCM
        {
        private:
            // Pointer to an AES block encryption implementation instance; never NULL.
            OTAES128E * const ap;
            // Only one is ever needed for any one call,
            // and calls cannot be made concurrently on any one instance.
            // Return appropriate temporary workspace.
#if defined(OTAESGCM_ALLOW_UNPADDED)
            virtual GGBWS::GCMEncryptWorkspace &getGCMEncryptWorkspace() = 0;
#endif
            virtual GGBWS::GCMEncryptPaddedWorkspace &getGCMEncryptPaddedWorkspace() = 0;
            virtual GGBWS::GCMDecryptWorkspace &getGCMDecryptWorkspace() = 0;

        public:
            // Create an instance pointing at a suitable AES block enc/dec implementation.
            // The AES impl should not carry logical state between operations,
            // but may hold temporary workspace or non-key/data-dependent state.
            constexpr OTAES128GCMGenericBase(OTAES128E *aptr) : ap(aptr) { }

            // Encrypt; true iff successful.
            // Plain text need not be padded to a block-size multiple.
#if defined(OTAESGCM_ALLOW_UNPADDED)
            virtual bool gcmEncrypt(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATA, uint8_t PDATALength,
                const uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag) override;

#endif
            // Encrypt; true if successful.
            // Plain-text must be an exact multiple of block length, eg padded.
            // This version should be smaller and faster and need less stack
            // than more generic gcmEncrypt().
            virtual bool gcmEncryptPadded(
                const uint8_t* key, const uint8_t* IV,
                const uint8_t* PDATAPadded, uint8_t PDATALength,
                const uint8_t* ADATA, uint8_t ADATALength,
                uint8_t* CDATA, uint8_t *tag) override;

            // Decrypt; true iff successful.
            // Crypto text must always be a multiple of block length.
            virtual bool gcmDecrypt(
                 const uint8_t* key, const uint8_t* IV,
                 const uint8_t* CDATA, uint8_t CDATALength,
                 const uint8_t* ADATA, uint8_t ADATALength,
                 const uint8_t* messageTag, uint8_t *PDATA) override;
        };
#if defined(OTAESGCM_ALLOW_NON_WORKSPACE)
    // Generic implementation, parameterised with type of underlying AES implementation.
    // Carries the AES working state with it.
    //
    // For security, as far as is reasonably possible:
    //   * the OTAESImpl methods should erase private state before returning.
    //   * the gcm function methods should erase private state before returning.
    template<class OTAESImpl = OTAESGCM::OTAES128E_default_t>
    class OTAES128GCMGeneric final : OTAESImpl, public OTAES128GCMGenericBase
        {
        private:
            // Minimum size of workspace required.
            constexpr static uint8_t workspaceRequiredAES = OTAESImpl::workspaceRequired;
            // Workspace is laid out starting with AES space
            // and followed by the GCM function workspace.
            // Note that we validate at compile time that at least the
            // minimum requirement is met.
            // The other non-minimal functions will need a runtime check.
            uint8_t workspaceAES[workspaceRequiredAES];

            // Union of temporary workspaces for the GCM functions.
            // Only one is ever needed for any one call,
            // and calls cannot be made concurrently on any one instance.
            union
                {
#if defined(OTAESGCM_ALLOW_UNPADDED)
                GGBWS::GCMEncryptWorkspace encWS;
#endif
                GGBWS::GCMEncryptPaddedWorkspace encPaddedWS;
                GGBWS::GCMDecryptWorkspace decWS;
                };
            // Return appropriate temporary workspace.
#if defined(OTAESGCM_ALLOW_UNPADDED)
            virtual GGBWS::GCMEncryptWorkspace &getGCMEncryptWorkspace() override { return(encWS); }
#endif
            virtual GGBWS::GCMEncryptPaddedWorkspace &getGCMEncryptPaddedWorkspace() override { return(encPaddedWS); }
            virtual GGBWS::GCMDecryptWorkspace &getGCMDecryptWorkspace() override { return(decWS); }

        public:
            // Construct an instance.
            constexpr OTAES128GCMGeneric() : OTAESImpl(workspaceAES, workspaceRequiredAES), OTAES128GCMGenericBase(this) { }
        };
#endif
    // Generic implementation, parameterised with type of underlying AES implementation.
    // Carries the AES working state with it.
    //
    // For security, as far as is reasonably possible:
    //   * the OTAESImpl methods should erase private state before returning.
    //   * the gcm function methods should erase private state before returning.
    template<class OTAESImpl = OTAESGCM::OTAES128E_default_t>
    class OTAES128GCMGenericWithWorkspace final : OTAESImpl, public OTAES128GCMGenericBase
        {
        private:
            // GCM workspace part of that passed into to constructor.
            uint8_t *const gcmWorkspace;

            // Return appropriate temporary workspace.
#if defined(OTAESGCM_ALLOW_UNPADDED)
            virtual GGBWS::GCMEncryptWorkspace &getGCMEncryptWorkspace() override { return(*(GGBWS::GCMEncryptWorkspace *)(gcmWorkspace)); }
#endif
            virtual GGBWS::GCMEncryptPaddedWorkspace &getGCMEncryptPaddedWorkspace() override { return(*(GGBWS::GCMEncryptPaddedWorkspace *)(gcmWorkspace)); }
            virtual GGBWS::GCMDecryptWorkspace &getGCMDecryptWorkspace() override { return(*(GGBWS::GCMDecryptWorkspace *)(gcmWorkspace)); }

        public:
            constexpr static uint8_t workspaceRequiredAES = OTAESImpl::workspaceRequired;

//            // on top of AES requirement.
//            // Implicitly this ensures total size can fit in a uint8_t also.
//            static_assert(GGBWS::gcmEncryptWorkspaceRequired + workspaceRequiredAES < 256U, "too big");
//            static_assert(GGBWS::gcmEncryptPaddedWorkspaceRequired + workspaceRequiredAES < 256U, "too big");
//            static_assert(GGBWS::gcmDecryptWorkspaceRequired + workspaceRequiredAES < 256U, "too big");

            // Suitable type to hold size of workspace required.
            typedef size_t workspacesize_t;

            // Minimum and maximum size of workspace required
            // (dependent on which function is to be called).
            constexpr static workspacesize_t workspaceRequiredMin =
                workspaceRequiredAES + GGBWS::minWS;
            constexpr static workspacesize_t workspaceRequiredMax =
                workspaceRequiredAES + GGBWS::maxWS;
            // Conservatively/statically request the maximum workspace needed.
            constexpr static workspacesize_t workspaceRequired = workspaceRequiredMax;
            // Construct an instance, supplied with workspace.
            // Pass the AES support class the leading part of the workspace.
            constexpr OTAES128GCMGenericWithWorkspace(uint8_t *const workspace, const workspacesize_t workspaceSize)
                : OTAESImpl(workspace, isWorkspaceSufficientMin(workspace, workspaceSize) ? workspaceRequiredAES : 0),
                  OTAES128GCMGenericBase(this),
                  gcmWorkspace(workspace + workspaceRequiredAES)
                { }
            // Verify that the workspace is adequate
            // at least for the least-demanding function.
            // This check may be made at compile time in common cases.
            static constexpr bool isWorkspaceSufficientMin(uint8_t *const workspace, const workspacesize_t workspaceSize)
                { return((NULL != workspace) && (workspaceSize >= workspaceRequiredMin)); }
            // Verify that the workspace is adequate
            // for the most-demanding function.
            // This check may be made at compile time in common cases.
            static constexpr bool isWorkspaceSufficient(uint8_t *const workspace, const workspacesize_t workspaceSize)
                { return((NULL != workspace) && (workspaceSize >= workspaceRequiredMax)); }

            // Workspace sufficient for gcmEncrypt().
            static constexpr workspacesize_t workspaceRequiredEnc = workspaceRequiredAES + (workspacesize_t) GGBWS::gcmEncryptWorkspaceRequired;
            // True if workspace sufficient for gcmEncrypt().
            static constexpr bool isWorkspaceSufficientEnc(uint8_t *const workspace, const workspacesize_t workspaceSize)
                { return((NULL != workspace) && (workspaceSize >= workspaceRequiredEnc)); }
            // Workspace sufficient for gcmEncryptPadded().
            static constexpr workspacesize_t workspaceRequiredEncPadded = workspaceRequiredAES + (workspacesize_t) GGBWS::gcmEncryptPaddedWorkspaceRequired;
            // True if workspace sufficient for gcmEncryptPadded().
            static constexpr bool isWorkspaceSufficientEncPadded(uint8_t *const workspace, const workspacesize_t workspaceSize)
                { return((NULL != workspace) && (workspaceSize >= workspaceRequiredEncPadded)); }
            // Workspace sufficient for gcmDecrypt().
            static constexpr workspacesize_t workspaceRequiredDec = workspaceRequiredAES + (workspacesize_t) GGBWS::gcmDecryptWorkspaceRequired;
            // True if workspace sufficient for gcmDecrypt().
            static constexpr bool isWorkspaceSufficientDec(uint8_t *const workspace, const workspacesize_t workspaceSize)
                { return((NULL != workspace) && (workspaceSize >= workspaceRequiredDec)); }
        };

#if defined(OTAESGCM_ALLOW_NON_WORKSPACE)
    // AES-GCM 128-bit-key fixed-size text (256-bit/32-byte) encryption/authentication function.
    // This is an adaptor/bridge function to ease outside use in simple cases
    // without explicit type/library dependencies, but use with care.
    // Stateless implementation: creates state on stack each time at cost of stack space
    // (which may be considerable and difficult to manage in an embedded system)
    // and at cost of time.
    // The state parameter is not used (is ignored) and should be NULL.
    // Other than the authtext, all sizes are fixed:
    //   * textSize is 32 (or zero if plaintext is NULL)
    //   * keySize is 16
    //   * nonceSize is 12
    //   * tagSize is 16
    // The plain-text (and identical cipher-text) size is picked to be
    // a multiple of the cipher's block size, or zero,
    // which implies likely requirement for padding of the plain text.
    // Note that the authenticated text size is not fixed, ie is zero or more bytes.
    // Returns true on success, false on failure.
    bool fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_STATELESS(void *,
            const uint8_t *key, const uint8_t *iv,
            const uint8_t *authtext, uint8_t authtextSize,
            const uint8_t *plaintext,
            uint8_t *ciphertextOut, uint8_t *tagOut);

    // AES-GCM 128-bit-key fixed-size text (256-bit/32-byte) decryption/authentication function.
    // This is an adaptor/bridge function to ease outside use in simple cases
    // without explicit type/library dependencies, but use with care.
    // Stateless implementation: creates state on stack each time at cost of stack space
    // (which may be considerable and difficult to manage in an embedded system)
    // and at cost of time.
    // The state parameter is not used (is ignored) and should be NULL.
    // Other than the authtext, all sizes are fixed:
    //   * textSize is 32 (or zero if ciphertext is NULL)
    //   * keySize is 16
    //   * nonceSize is 12
    //   * tagSize is 16
    // The plain-text (and identical cipher-text) size is picked to be
    // a multiple of the cipher's block size, or zero,
    // which implies likely requirement for padding of the plain text.
    // Note that the authenticated text size is not fixed, ie is zero or more bytes.
    // Decrypts/authenticates the output of fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_STATELESS.)
    // Returns true on success, false on failure.
    bool fixed32BTextSize12BNonce16BTagSimpleDec_DEFAULT_STATELESS(void *state,
            const uint8_t *key, const uint8_t *iv,
            const uint8_t *authtext, uint8_t authtextSize,
            const uint8_t *ciphertext, const uint8_t *tag,
            uint8_t *plaintextOut);

#endif
    // AES-GCM 128-bit-key fixed-size text (256-bit/32-byte) encryption/authentication function using work space passed in.
    // This is an adaptor/bridge function to ease outside use in simple cases
    // without explicit type/library dependencies, but use with care.
    // A workspace is passed in (and cleared on exit);
    // this routine will fail (safely, returning false) if the workspace is NULL or too small.
    // The workspace requirement depends on the implementation used.
    // Other than the authtext, all sizes are fixed:
    //   * textSize is 32 (or zero if plaintext is NULL)
    //   * keySize is 16
    //   * nonceSize is 12
    //   * tagSize is 16
    // The plain-text (and identical cipher-text) size is picked to be
    // a multiple of the cipher's block size, or zero,
    // which implies likely requirement for padding of the plain text.
    // Note that the authenticated text size is not fixed, ie is zero or more bytes.
    // Returns true on success, false on failure.
    bool fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_WITH_LWORKSPACE(
            uint8_t *workspace, size_t workspaceSize,
            const uint8_t *key, const uint8_t *iv,
            const uint8_t *authtext, uint8_t authtextSize,
            const uint8_t *plaintext,
            uint8_t *ciphertextOut, uint8_t *tagOut);

    // AES-GCM 128-bit-key fixed-size text (256-bit/32-byte) decryption/authentication function using work space passed in.
    // This is an adaptor/bridge function to ease outside use in simple cases
    // without explicit type/library dependencies, but use with care.
    // A workspace is passed in (and cleared on exit);
    // this routine will fail (safely, returning false) if the workspace is NULL or too small.
    // The workspace requirement depends on the implementation used.
    // Other than the authtext, all sizes are fixed:
    //   * textSize is 32 (or zero if ciphertext is NULL)
    //   * keySize is 16
    //   * nonceSize is 12
    //   * tagSize is 16
    // The plain-text (and identical cipher-text) size is picked to be
    // a multiple of the cipher's block size, or zero,
    // which implies likely requirement for padding of the plain text.
    // Note that the authenticated text size is not fixed, ie is zero or more bytes.
    // Decrypts/authenticates the output of fixed32BTextSize12BNonce16BTagSimpleEnc_DEFAULT_STATELESS.)
    // Returns true on success, false on failure.
    bool fixed32BTextSize12BNonce16BTagSimpleDec_DEFAULT_WITH_LWORKSPACE(
            uint8_t *workspace, size_t workspaceSize,
            const uint8_t *key, const uint8_t *iv,
            const uint8_t *authtext, uint8_t authtextSize,
            const uint8_t *ciphertext, const uint8_t *tag,
            uint8_t *plaintextOut);
    }

/**
# (20170713) Flash investigation notes:

## Commits:
### Working
- V0p2:         a56a21c
- OTRadioLink:  eff6d4b
- OTAESGCM:     3e3bd24

This is before padded functions are introduced.
Slight increase in REV10_AS_BHR flash usage.

### Testing AESGCM Original
| COMMIT  | DORM1   | REV10_BHR | CHANGE    |
| :------ | ------: | --------: | --------: |
| 3e3bd24 |   31968 |     30180 |       n/a |
| ec60f97 |   32438 |     30652 | +470/+472 | Padded functions?
| d7bba44 |   32462 |     30676 |   +24/+24 |
| d7bba44 |   32462 |     30676 |   +24/+24 |

### Testing AESGCM on flashTesting Branch
| COMMIT  | DORM1   | REV10_BHR | CHANGE    |
| :------ | ------: | --------: | --------: |
| d7bba44 |   32462 |     30676 |       n/a |
| 093311c |   31968 |     30180 |       n/a | Should be equivalent to 3e3bd24
| c6dd3a1 |   31968 |     30180 |       n/a |
| a48ad06 |   32012 |     30224 |   +44/+44 | Reintroduced workspaces but avoided using padded functions
| 770183e |   32504 |     30718 | +492/+494 | Reintroduced padded top level functions but avoided using them
| ??????? |   31844 |     30056 | -168/-168 | Removed unpadded functions (compared to a48ad06)
| c70fa80 |   33206 |     31596 | +1362/+1540 |
| e2eef7a |   31512 |     29886 |       n/a | Disabled fprintf on arduino. Slight? saving over before refactoring/extending OTAESGCM.

 */



#endif
