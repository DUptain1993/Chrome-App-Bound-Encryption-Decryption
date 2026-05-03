// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <bcrypt.h>
#include <vector>
#include <optional>

namespace Crypto {

    class AesGcm {
    public:
        // Decrypt ABE-encrypted data.
        // Accepts both "v20" (App-Bound Encryption) and "v10" (legacy DPAPI-backed) prefixes.
        // If isLegacyV10 is non-null, it is set to true when a v10-prefixed blob is decrypted
        // (callers use this to skip the 32-byte ABE metadata header that v20 cookies carry).
        static std::optional<std::vector<uint8_t>> Decrypt(
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& encryptedData,
            bool* isLegacyV10 = nullptr);
    };

}
