#include "auth_state.h"

namespace witcher {

    namespace {
        CRITICAL_SECTION g_auth_lock;
        AuthState g_auth_state;
    }

    void InitAuthState() {
        InitializeCriticalSection(&g_auth_lock);
    }

    void FreeAuthState() {
        DeleteCriticalSection(&g_auth_lock);
    }

    void SetAuthTokens(
        const std::wstring& username,
        const std::string& accessToken,
        const std::string& refreshToken,
        long long accessExpiresAtUnix,
        long long refreshExpiresAtUnix
    ) {
        EnterCriticalSection(&g_auth_lock);

        g_auth_state.authenticated = true;
        g_auth_state.username = username;
        g_auth_state.accessToken = accessToken;
        g_auth_state.refreshToken = refreshToken;
        g_auth_state.accessExpiresAtUnix = accessExpiresAtUnix;
        g_auth_state.refreshExpiresAtUnix = refreshExpiresAtUnix;

        LeaveCriticalSection(&g_auth_lock);
    }

    void ClearAuthTokens() {
        EnterCriticalSection(&g_auth_lock);

        g_auth_state = AuthState{};

        LeaveCriticalSection(&g_auth_lock);
    }

    bool IsAuthenticated() {
        EnterCriticalSection(&g_auth_lock);

        bool result = g_auth_state.authenticated;

        LeaveCriticalSection(&g_auth_lock);
        return result;
    }

    std::wstring GetAuthenticatedUsername() {
        EnterCriticalSection(&g_auth_lock);

        std::wstring result = g_auth_state.username;

        LeaveCriticalSection(&g_auth_lock);
        return result;
    }

    std::string GetAccessToken() {
        EnterCriticalSection(&g_auth_lock);

        std::string result = g_auth_state.accessToken;

        LeaveCriticalSection(&g_auth_lock);
        return result;
    }

    std::string GetRefreshToken() {
        EnterCriticalSection(&g_auth_lock);

        std::string result = g_auth_state.refreshToken;

        LeaveCriticalSection(&g_auth_lock);
        return result;
    }
    bool GetTokenExpirations(
        long long* accessExpiresAtUnix,
        long long* refreshExpiresAtUnix
    ) {
        EnterCriticalSection(&g_auth_lock);

        if (accessExpiresAtUnix) {
            *accessExpiresAtUnix = g_auth_state.accessExpiresAtUnix;
        }

        if (refreshExpiresAtUnix) {
            *refreshExpiresAtUnix = g_auth_state.refreshExpiresAtUnix;
        }

        bool result = g_auth_state.authenticated;

        LeaveCriticalSection(&g_auth_lock);
        return result;
    }
}