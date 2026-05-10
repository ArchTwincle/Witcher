#include "http_client.h"

#include <windows.h>
#include <winhttp.h>

#include <string>

#pragma comment(lib, "winhttp.lib")

namespace witcher {

    namespace {

        std::string WideToUtf8(const std::wstring& value) {
            if (value.empty()) {
                return {};
            }

            int size = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                -1,
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (size <= 0) {
                return {};
            }

            std::string result(size - 1, '\0');

            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                -1,
                result.data(),
                size,
                nullptr,
                nullptr
            );

            return result;
        }

        std::wstring Utf8ToWide(const std::string& value) {
            if (value.empty()) {
                return {};
            }

            int size = MultiByteToWideChar(
                CP_UTF8,
                0,
                value.c_str(),
                -1,
                nullptr,
                0
            );

            if (size <= 0) {
                return {};
            }

            std::wstring result(size - 1, L'\0');

            MultiByteToWideChar(
                CP_UTF8,
                0,
                value.c_str(),
                -1,
                result.data(),
                size
            );

            return result;
        }

        std::string EscapeJson(const std::string& value) {
            std::string result;

            for (char ch : value) {
                switch (ch) {
                case '\\':
                    result += "\\\\";
                    break;

                case '"':
                    result += "\\\"";
                    break;

                case '\n':
                    result += "\\n";
                    break;

                case '\r':
                    result += "\\r";
                    break;

                case '\t':
                    result += "\\t";
                    break;

                default:
                    result += ch;
                    break;
                }
            }

            return result;
        }

        std::string ExtractJsonString(const std::string& json, const std::string& key) {
            std::string pattern = "\"" + key + "\"";

            size_t keyPos = json.find(pattern);
            if (keyPos == std::string::npos) {
                return {};
            }

            size_t colonPos = json.find(':', keyPos);
            if (colonPos == std::string::npos) {
                return {};
            }

            size_t firstQuote = json.find('"', colonPos + 1);
            if (firstQuote == std::string::npos) {
                return {};
            }

            size_t secondQuote = json.find('"', firstQuote + 1);
            if (secondQuote == std::string::npos) {
                return {};
            }

            return json.substr(firstQuote + 1, secondQuote - firstQuote - 1);
        }

        bool ReadHttpResponse(HINTERNET request, std::string* response) {
            if (!response) {
                return false;
            }

            response->clear();

            while (true) {
                DWORD availableSize = 0;

                if (!WinHttpQueryDataAvailable(request, &availableSize)) {
                    return false;
                }

                if (availableSize == 0) {
                    break;
                }

                std::string buffer(availableSize, '\0');
                DWORD downloadedSize = 0;

                if (!WinHttpReadData(
                    request,
                    buffer.data(),
                    availableSize,
                    &downloadedSize
                )) {
                    return false;
                }

                buffer.resize(downloadedSize);
                *response += buffer;
            }

            return true;
        }

        DWORD QueryHttpStatusCode(HINTERNET request) {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);

            BOOL ok = WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &statusCodeSize,
                WINHTTP_NO_HEADER_INDEX
            );

            if (!ok) {
                return 0;
            }

            return statusCode;
        }

        void AllowLocalSelfSignedCertificate(HINTERNET request) {
            DWORD securityFlags =
                SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            WinHttpSetOption(
                request,
                WINHTTP_OPTION_SECURITY_FLAGS,
                &securityFlags,
                sizeof(securityFlags)
            );
        }

    } // namespace

    LoginResult LoginRequest(
        const std::wstring& username,
        const std::wstring& password
    ) {
        LoginResult result;
        result.username = username;

        HINTERNET session = WinHttpOpen(
            L"WitcherTrayService/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!session) {
            result.errorCode = GetLastError();
            return result;
        }

        HINTERNET connect = WinHttpConnect(
            session,
            L"localhost",
            8443,
            0
        );

        if (!connect) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(session);
            return result;
        }

        HINTERNET request = WinHttpOpenRequest(
            connect,
            L"POST",
            L"/api/auth/login",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        if (!request) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        AllowLocalSelfSignedCertificate(request);

        std::string usernameUtf8 = WideToUtf8(username);
        std::string passwordUtf8 = WideToUtf8(password);

        std::string body =
            "{"
            "\"username\":\"" + EscapeJson(usernameUtf8) + "\","
            "\"password\":\"" + EscapeJson(passwordUtf8) + "\""
            "}";

        std::wstring headers = L"Content-Type: application/json\r\n";

        BOOL sent = WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.length()),
            reinterpret_cast<LPVOID>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0
        );

        if (!sent) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        BOOL received = WinHttpReceiveResponse(request, nullptr);

        if (!received) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        DWORD statusCode = QueryHttpStatusCode(request);

        if (statusCode != 200) {
            result.errorCode = static_cast<long>(statusCode);
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        std::string response;

        if (!ReadHttpResponse(request, &response)) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        result.accessToken = ExtractJsonString(response, "accessToken");
        result.refreshToken = ExtractJsonString(response, "refreshToken");

        if (!result.accessToken.empty() && !result.refreshToken.empty()) {
            result.success = true;
            result.errorCode = 0;
        }
        else {
            result.success = false;
            result.errorCode = ERROR_INVALID_DATA;
        }

        return result;
    }

    RefreshResult RefreshTokenRequest(
        const std::string& refreshToken
    ) {
        RefreshResult result;

        HINTERNET session = WinHttpOpen(
            L"WitcherTrayService/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!session) {
            result.errorCode = GetLastError();
            return result;
        }

        HINTERNET connect = WinHttpConnect(
            session,
            L"localhost",
            8443,
            0
        );

        if (!connect) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(session);
            return result;
        }

        HINTERNET request = WinHttpOpenRequest(
            connect,
            L"POST",
            L"/api/auth/refresh",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        if (!request) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        AllowLocalSelfSignedCertificate(request);

        std::string body =
            "{"
            "\"refreshToken\":\"" + EscapeJson(refreshToken) + "\""
            "}";

        std::wstring headers = L"Content-Type: application/json\r\n";

        BOOL sent = WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.length()),
            reinterpret_cast<LPVOID>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0
        );

        if (!sent) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        BOOL received = WinHttpReceiveResponse(request, nullptr);

        if (!received) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        DWORD statusCode = QueryHttpStatusCode(request);

        if (statusCode != 200) {
            result.errorCode = static_cast<long>(statusCode);
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        std::string response;

        if (!ReadHttpResponse(request, &response)) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        result.accessToken = ExtractJsonString(response, "accessToken");
        result.refreshToken = ExtractJsonString(response, "refreshToken");

        if (!result.accessToken.empty() && !result.refreshToken.empty()) {
            result.success = true;
            result.errorCode = 0;
        }
        else {
            result.success = false;
            result.errorCode = ERROR_INVALID_DATA;
        }

        return result;
    }

    LicenseCheckResult CheckLicenseRequest(
        const std::string& accessToken,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    ) {
        LicenseCheckResult result;

        HINTERNET session = WinHttpOpen(
            L"WitcherTrayService/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!session) {
            result.errorCode = GetLastError();
            return result;
        }

        HINTERNET connect = WinHttpConnect(
            session,
            L"localhost",
            8443,
            0
        );

        if (!connect) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(session);
            return result;
        }

        HINTERNET request = WinHttpOpenRequest(
            connect,
            L"POST",
            L"/api/licenses/check",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        if (!request) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        AllowLocalSelfSignedCertificate(request);

        std::string body =
            "{"
            "\"licenseCode\":\"" + EscapeJson(licenseCode) + "\","
            "\"macAddress\":\"" + EscapeJson(macAddress) + "\","
            "\"productId\":\"" + EscapeJson(productId) + "\""
            "}";

        std::string headersUtf8 =
            "Content-Type: application/json\r\n"
            "Authorization: Bearer " + accessToken + "\r\n";

        std::wstring headers = Utf8ToWide(headersUtf8);

        BOOL sent = WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.length()),
            reinterpret_cast<LPVOID>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0
        );

        if (!sent) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        BOOL received = WinHttpReceiveResponse(request, nullptr);

        if (!received) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        DWORD statusCode = QueryHttpStatusCode(request);

        if (statusCode != 200) {
            result.errorCode = static_cast<long>(statusCode);
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        std::string response;

        if (!ReadHttpResponse(request, &response)) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        if (!response.empty()) {
            result.success = true;
            result.errorCode = 0;
            result.licenseTicket = response;
        }
        else {
            result.success = false;
            result.errorCode = ERROR_INVALID_DATA;
        }

        return result;
    }

    LicenseActivateResult ActivateLicenseRequest(
        const std::string& accessToken,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    ) {
        LicenseActivateResult result;

        HINTERNET session = WinHttpOpen(
            L"WitcherTrayService/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!session) {
            result.errorCode = GetLastError();
            return result;
        }

        HINTERNET connect = WinHttpConnect(
            session,
            L"localhost",
            8443,
            0
        );

        if (!connect) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(session);
            return result;
        }

        HINTERNET request = WinHttpOpenRequest(
            connect,
            L"POST",
            L"/api/licenses/activate",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );

        if (!request) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        AllowLocalSelfSignedCertificate(request);

        std::string body =
            "{"
            "\"licenseCode\":\"" + EscapeJson(licenseCode) + "\","
            "\"macAddress\":\"" + EscapeJson(macAddress) + "\","
            "\"productId\":\"" + EscapeJson(productId) + "\""
            "}";

        std::string headersUtf8 =
            "Content-Type: application/json\r\n"
            "Authorization: Bearer " + accessToken + "\r\n";

        std::wstring headers = Utf8ToWide(headersUtf8);

        BOOL sent = WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.length()),
            reinterpret_cast<LPVOID>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0
        );

        if (!sent) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        BOOL received = WinHttpReceiveResponse(request, nullptr);

        if (!received) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        DWORD statusCode = QueryHttpStatusCode(request);

        if (statusCode != 200) {
            result.errorCode = static_cast<long>(statusCode);
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        std::string response;

        if (!ReadHttpResponse(request, &response)) {
            result.errorCode = GetLastError();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return result;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);

        result.success = true;
        result.errorCode = 0;
        result.licenseTicket = response;

        return result;
    }

}