#include "jwt_utils.h"

#include <windows.h>

#include <string>
#include <vector>

namespace witcher {

    namespace {

        std::string Base64UrlToBase64(std::string value) {
            for (char& ch : value) {
                if (ch == '-') {
                    ch = '+';
                }
                else if (ch == '_') {
                    ch = '/';
                }
            }

            while (value.size() % 4 != 0) {
                value += '=';
            }

            return value;
        }

        bool Base64Decode(const std::string& input, std::string* output) {
            if (!output) {
                return false;
            }

            DWORD requiredSize = 0;

            if (!CryptStringToBinaryA(
                input.c_str(),
                static_cast<DWORD>(input.size()),
                CRYPT_STRING_BASE64,
                nullptr,
                &requiredSize,
                nullptr,
                nullptr
            )) {
                return false;
            }

            std::vector<BYTE> buffer(requiredSize);

            if (!CryptStringToBinaryA(
                input.c_str(),
                static_cast<DWORD>(input.size()),
                CRYPT_STRING_BASE64,
                buffer.data(),
                &requiredSize,
                nullptr,
                nullptr
            )) {
                return false;
            }

            output->assign(
                reinterpret_cast<const char*>(buffer.data()),
                requiredSize
            );

            return true;
        }

        bool ExtractJsonNumber(
            const std::string& json,
            const std::string& key,
            long long* value
        ) {
            if (!value) {
                return false;
            }

            std::string pattern = "\"" + key + "\"";

            size_t keyPos = json.find(pattern);
            if (keyPos == std::string::npos) {
                return false;
            }

            size_t colonPos = json.find(':', keyPos);
            if (colonPos == std::string::npos) {
                return false;
            }

            size_t numberStart = json.find_first_of("0123456789", colonPos + 1);
            if (numberStart == std::string::npos) {
                return false;
            }

            size_t numberEnd = json.find_first_not_of("0123456789", numberStart);
            std::string numberText = json.substr(numberStart, numberEnd - numberStart);

            try {
                *value = std::stoll(numberText);
                return true;
            }
            catch (...) {
                return false;
            }
        }

    }

    bool GetJwtExpirationUnix(
        const std::string& jwt,
        long long* expirationUnix
    ) {
        if (!expirationUnix) {
            return false;
        }

        size_t firstDot = jwt.find('.');
        if (firstDot == std::string::npos) {
            return false;
        }

        size_t secondDot = jwt.find('.', firstDot + 1);
        if (secondDot == std::string::npos) {
            return false;
        }

        std::string payloadBase64Url = jwt.substr(
            firstDot + 1,
            secondDot - firstDot - 1
        );

        std::string payloadBase64 = Base64UrlToBase64(payloadBase64Url);

        std::string payloadJson;
        if (!Base64Decode(payloadBase64, &payloadJson)) {
            return false;
        }

        return ExtractJsonNumber(payloadJson, "exp", expirationUnix);
    }

}