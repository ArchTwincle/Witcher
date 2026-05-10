#pragma once

#include <string>

namespace witcher {

    struct LoginResult {
        bool success = false;
        long errorCode = 0;

        std::string accessToken;
        std::string refreshToken;
        std::wstring username;
    };

    struct RefreshResult {
        bool success = false;
        long errorCode = 0;

        std::string accessToken;
        std::string refreshToken;
    };

    struct LicenseCheckResult {
        bool success = false;
        long errorCode = 0;

        std::string licenseTicket;
    };

    struct LicenseActivateResult {
        bool success = false;
        long errorCode = 0;

        std::string licenseTicket;
    };

    LoginResult LoginRequest(
        const std::wstring& username,
        const std::wstring& password
    );

    RefreshResult RefreshTokenRequest(
        const std::string& refreshToken
    );

    LicenseCheckResult CheckLicenseRequest(
        const std::string& accessToken,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    );

    LicenseActivateResult ActivateLicenseRequest(
        const std::string& accessToken,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    );

}