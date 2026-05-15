#pragma once

#include <windows.h>
#include <string>

namespace witcher {

    struct AuthState {
        bool authenticated = false;

        std::wstring username;

        std::string accessToken;
        std::string refreshToken;

        long long accessExpiresAtUnix = 0;
        long long refreshExpiresAtUnix = 0;
    };

    void InitAuthState();
    void FreeAuthState();

    void SetAuthTokens(
        const std::wstring& username,
        const std::string& accessToken,
        const std::string& refreshToken,
        long long accessExpiresAtUnix = 0,
        long long refreshExpiresAtUnix = 0
    );

    void ClearAuthTokens();

    bool IsAuthenticated();

    std::wstring GetAuthenticatedUsername();

    std::string GetAccessToken();
    std::string GetRefreshToken();

    bool GetTokenExpirations(
        long long* accessExpiresAtUnix,
        long long* refreshExpiresAtUnix
    );

}