#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>

#include <filesystem>
#include <string>
#include <vector>
#include <ctime>

#include "common.h"
#include "WitcherControl_h.h"
#include "auth_state.h"
#include "http_client.h"
#include "jwt_utils.h"
#include "license_state.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

    SERVICE_STATUS_HANDLE g_status_handle = nullptr;
    SERVICE_STATUS g_status{};
    HANDLE g_stop_event = nullptr;
    HANDLE g_refresh_thread = nullptr;
    HANDLE g_license_thread = nullptr;
    CRITICAL_SECTION g_process_lock;
    std::vector<PROCESS_INFORMATION> g_children;

    void SetServiceStatusValue(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
        g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_status.dwCurrentState = state;

        if (state == SERVICE_RUNNING) {
            g_status.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
        }
        else {
            g_status.dwControlsAccepted = 0;
        }

        g_status.dwWin32ExitCode = win32_exit_code;
        g_status.dwServiceSpecificExitCode = 0;
        g_status.dwCheckPoint = 0;
        g_status.dwWaitHint = wait_hint;

        SetServiceStatus(g_status_handle, &g_status);
    }

    std::filesystem::path GetModuleDirectory() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        return std::filesystem::path(path).parent_path();
    }

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

    long long ExtractJsonNumber(
        const std::string& json,
        const std::string& key
    ) {
        std::string pattern = "\"" + key + "\"";

        size_t keyPos = json.find(pattern);
        if (keyPos == std::string::npos) {
            return 0;
        }

        size_t colonPos = json.find(':', keyPos);
        if (colonPos == std::string::npos) {
            return 0;
        }

        size_t numberStart = json.find_first_of("0123456789", colonPos + 1);
        if (numberStart == std::string::npos) {
            return 0;
        }

        size_t numberEnd = json.find_first_not_of("0123456789", numberStart);

        std::string numberText = json.substr(
            numberStart,
            numberEnd - numberStart
        );

        try {
            return std::stoll(numberText);
        }
        catch (...) {
            return 0;
        }
    }

    std::string ExtractJsonString(
        const std::string& json,
        const std::string& key
    ) {
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

    void StoreLicenseTicket(
        const std::string& licenseTicket,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    ) {
        long long ticketLifetimeSeconds = ExtractJsonNumber(
            licenseTicket,
            "ticketLifetimeSeconds"
        );

        std::string expirationDate = ExtractJsonString(
            licenseTicket,
            "expirationDate"
        );

        witcher::SetLicenseTicket(
            licenseTicket,
            ticketLifetimeSeconds,
            expirationDate,
            licenseCode,
            macAddress,
            productId
        );
    }

    bool CopyStringToRpcBuffer(
        const std::wstring& source,
        wchar_t* destination,
        unsigned long destinationCapacity
    ) {
        if (!destination || destinationCapacity == 0) {
            return false;
        }

        destination[0] = L'\0';

        if (source.empty()) {
            return true;
        }

        wcsncpy_s(
            destination,
            destinationCapacity,
            source.c_str(),
            _TRUNCATE
        );

        return true;
    }

    bool IsSessionAlreadyStarted(DWORD session_id) {
        EnterCriticalSection(&g_process_lock);

        for (auto it = g_children.begin(); it != g_children.end();) {
            DWORD exit_code = 0;

            if (GetExitCodeProcess(it->hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
                CloseHandle(it->hProcess);
                CloseHandle(it->hThread);
                it = g_children.erase(it);
                continue;
            }

            DWORD child_session = 0;
            if (ProcessIdToSessionId(it->dwProcessId, &child_session) && child_session == session_id) {
                LeaveCriticalSection(&g_process_lock);
                return true;
            }

            ++it;
        }

        LeaveCriticalSection(&g_process_lock);
        return false;
    }

    bool LaunchTrayAppInSession(DWORD session_id) {
        if (session_id == 0 || IsSessionAlreadyStarted(session_id)) {
            return false;
        }

        HANDLE user_token = nullptr;
        if (!WTSQueryUserToken(session_id, &user_token)) {
            return false;
        }

        HANDLE primary_token = nullptr;
        SECURITY_ATTRIBUTES token_attributes{};
        token_attributes.nLength = sizeof(token_attributes);

        if (!DuplicateTokenEx(
            user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            &token_attributes,
            SecurityIdentification,
            TokenPrimary,
            &primary_token)) {
            CloseHandle(user_token);
            return false;
        }

        CloseHandle(user_token);

        void* environment = nullptr;
        CreateEnvironmentBlock(&environment, primary_token, FALSE);

        const auto module_directory = GetModuleDirectory();
        const auto app_path = module_directory / witcher::kTrayAppExeName;

        std::wstring command_line = L"\"" + app_path.wstring() + L"\" --hidden --service-child";

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

        PROCESS_INFORMATION process{};

        const DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT;

        BOOL created = CreateProcessAsUserW(
            primary_token,
            app_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            creation_flags,
            environment,
            module_directory.c_str(),
            &startup,
            &process
        );

        if (environment) {
            DestroyEnvironmentBlock(environment);
        }

        CloseHandle(primary_token);

        if (!created) {
            return false;
        }

        EnterCriticalSection(&g_process_lock);
        g_children.push_back(process);
        LeaveCriticalSection(&g_process_lock);

        return true;
    }

    void LaunchTrayAppsInExistingSessions() {
        WTS_SESSION_INFOW* sessions = nullptr;
        DWORD count = 0;

        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
            return;
        }

        for (DWORD i = 0; i < count; ++i) {
            const auto& session = sessions[i];

            if (session.SessionId != 0 &&
                (session.State == WTSActive ||
                    session.State == WTSConnected ||
                    session.State == WTSDisconnected)) {
                LaunchTrayAppInSession(session.SessionId);
            }
        }

        WTSFreeMemory(sessions);
    }

    void TerminateChildren() {
        EnterCriticalSection(&g_process_lock);

        for (auto& child : g_children) {
            DWORD exit_code = 0;

            if (GetExitCodeProcess(child.hProcess, &exit_code) && exit_code == STILL_ACTIVE) {
                TerminateProcess(child.hProcess, 0);
                WaitForSingleObject(child.hProcess, 5000);
            }

            CloseHandle(child.hProcess);
            CloseHandle(child.hThread);
        }

        g_children.clear();

        LeaveCriticalSection(&g_process_lock);
    }

    DWORD WINAPI TokenRefreshThread(void*) {
        while (true) {
            if (!witcher::IsAuthenticated()) {
                DWORD waitResult = WaitForSingleObject(g_stop_event, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long accessExpiresAtUnix = 0;
            long long refreshExpiresAtUnix = 0;

            if (!witcher::GetTokenExpirations(
                &accessExpiresAtUnix,
                &refreshExpiresAtUnix
            )) {
                DWORD waitResult = WaitForSingleObject(g_stop_event, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            const long long nowUnix = static_cast<long long>(std::time(nullptr));

            if (refreshExpiresAtUnix > 0 && nowUnix >= refreshExpiresAtUnix) {
                witcher::ClearLicenseTicket();
                witcher::ClearAuthTokens();

                DWORD waitResult = WaitForSingleObject(g_stop_event, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long secondsUntilRefresh = 60;

            if (accessExpiresAtUnix > 0) {
                secondsUntilRefresh = accessExpiresAtUnix - nowUnix - 60;
            }

            if (secondsUntilRefresh < 5) {
                secondsUntilRefresh = 5;
            }

            DWORD waitMilliseconds = static_cast<DWORD>(secondsUntilRefresh * 1000);

            DWORD waitResult = WaitForSingleObject(g_stop_event, waitMilliseconds);
            if (waitResult == WAIT_OBJECT_0) {
                break;
            }

            if (!witcher::IsAuthenticated()) {
                continue;
            }

            std::string currentRefreshToken = witcher::GetRefreshToken();
            std::wstring currentUsername = witcher::GetAuthenticatedUsername();

            if (currentRefreshToken.empty()) {
                witcher::ClearLicenseTicket();
                witcher::ClearAuthTokens();
                continue;
            }

            witcher::RefreshResult refreshResult =
                witcher::RefreshTokenRequest(currentRefreshToken);

            if (!refreshResult.success) {
                DWORD retryWaitResult = WaitForSingleObject(g_stop_event, 30000);
                if (retryWaitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long newAccessExpiresAtUnix = 0;
            long long newRefreshExpiresAtUnix = 0;

            witcher::GetJwtExpirationUnix(
                refreshResult.accessToken,
                &newAccessExpiresAtUnix
            );

            witcher::GetJwtExpirationUnix(
                refreshResult.refreshToken,
                &newRefreshExpiresAtUnix
            );

            witcher::SetAuthTokens(
                currentUsername,
                refreshResult.accessToken,
                refreshResult.refreshToken,
                newAccessExpiresAtUnix,
                newRefreshExpiresAtUnix
            );
        }

        return 0;
    }

    DWORD WINAPI LicenseRefreshThread(void*) {
        while (true) {
            if (!witcher::IsAuthenticated() || !witcher::HasLicenseTicket()) {
                DWORD waitResult = WaitForSingleObject(g_stop_event, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long ticketSavedAtUnix = 0;
            long long ticketLifetimeSeconds = 0;
            std::string licenseCode;
            std::string macAddress;
            std::string productId;

            if (!witcher::GetLicenseRefreshRequestInfo(
                &ticketSavedAtUnix,
                &ticketLifetimeSeconds,
                &licenseCode,
                &macAddress,
                &productId
            )) {
                witcher::ClearLicenseTicket();

                DWORD waitResult = WaitForSingleObject(g_stop_event, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long secondsUntilRefresh = 60;

            if (ticketLifetimeSeconds > 0) {
                const long long nowUnix = static_cast<long long>(std::time(nullptr));
                const long long refreshAtUnix =
                    ticketSavedAtUnix + ticketLifetimeSeconds - 60;

                secondsUntilRefresh = refreshAtUnix - nowUnix;
            }

            if (secondsUntilRefresh < 5) {
                secondsUntilRefresh = 5;
            }

            DWORD waitMilliseconds = static_cast<DWORD>(secondsUntilRefresh * 1000);

            DWORD waitResult = WaitForSingleObject(g_stop_event, waitMilliseconds);
            if (waitResult == WAIT_OBJECT_0) {
                break;
            }

            if (!witcher::IsAuthenticated()) {
                witcher::ClearLicenseTicket();
                continue;
            }

            std::string accessToken = witcher::GetAccessToken();

            if (accessToken.empty()) {
                witcher::ClearLicenseTicket();
                continue;
            }

            witcher::LicenseCheckResult licenseResult =
                witcher::CheckLicenseRequest(
                    accessToken,
                    licenseCode,
                    macAddress,
                    productId
                );

            if (!licenseResult.success) {
                DWORD retryWaitResult = WaitForSingleObject(g_stop_event, 30000);
                if (retryWaitResult == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            StoreLicenseTicket(
                licenseResult.licenseTicket,
                licenseCode,
                macAddress,
                productId
            );
        }

        return 0;
    }

    DWORD WINAPI RpcServerThread(void*) {
        RPC_STATUS status = RpcServerUseProtseqEpW(
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(witcher::kRpcEndpoint)),
            nullptr
        );

        if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
            SetEvent(g_stop_event);
            return status;
        }

        status = RpcServerRegisterIf2(
            WitcherControl_v1_0_s_ifspec,
            nullptr,
            nullptr,
            RPC_IF_ALLOW_LOCAL_ONLY,
            RPC_C_LISTEN_MAX_CALLS_DEFAULT,
            static_cast<unsigned>(-1),
            nullptr
        );

        if (status != RPC_S_OK) {
            SetEvent(g_stop_event);
            return status;
        }

        status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
        if (status != RPC_S_OK) {
            SetEvent(g_stop_event);
        }

        return status;
    }

    DWORD WINAPI ServiceControlHandlerEx(DWORD control, DWORD event_type, void* event_data, void*) {
        if (control == SERVICE_CONTROL_SESSIONCHANGE) {
            if (event_type == WTS_SESSION_LOGON ||
                event_type == WTS_SESSION_UNLOCK ||
                event_type == WTS_CONSOLE_CONNECT ||
                event_type == WTS_REMOTE_CONNECT) {
                auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(event_data);

                if (notification && notification->dwSessionId != 0) {
                    LaunchTrayAppInSession(notification->dwSessionId);
                }
            }

            return NO_ERROR;
        }

        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    void WINAPI ServiceMain(DWORD, LPWSTR*) {
        g_status_handle = RegisterServiceCtrlHandlerExW(
            witcher::kServiceName,
            ServiceControlHandlerEx,
            nullptr
        );

        if (!g_status_handle) {
            return;
        }

        SetServiceStatusValue(SERVICE_START_PENDING, NO_ERROR, 3000);

        InitializeCriticalSection(&g_process_lock);
        witcher::InitAuthState();
        witcher::InitLicenseState();

        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_stop_event) {
            SetServiceStatusValue(SERVICE_STOPPED, GetLastError());
            witcher::FreeLicenseState();
            witcher::FreeAuthState();
            DeleteCriticalSection(&g_process_lock);
            return;
        }

        HANDLE rpc_thread = CreateThread(nullptr, 0, RpcServerThread, nullptr, 0, nullptr);
        if (!rpc_thread) {
            CloseHandle(g_stop_event);
            g_stop_event = nullptr;
            SetServiceStatusValue(SERVICE_STOPPED, GetLastError());
            witcher::FreeLicenseState();
            witcher::FreeAuthState();
            DeleteCriticalSection(&g_process_lock);
            return;
        }

        g_refresh_thread = CreateThread(
            nullptr,
            0,
            TokenRefreshThread,
            nullptr,
            0,
            nullptr
        );

        if (!g_refresh_thread) {
            RpcMgmtStopServerListening(nullptr);
            WaitForSingleObject(rpc_thread, 5000);
            RpcServerUnregisterIf(WitcherControl_v1_0_s_ifspec, nullptr, FALSE);
            CloseHandle(rpc_thread);

            CloseHandle(g_stop_event);
            g_stop_event = nullptr;

            SetServiceStatusValue(SERVICE_STOPPED, GetLastError());

            witcher::FreeLicenseState();
            witcher::FreeAuthState();
            DeleteCriticalSection(&g_process_lock);
            return;
        }

        g_license_thread = CreateThread(
            nullptr,
            0,
            LicenseRefreshThread,
            nullptr,
            0,
            nullptr
        );

        if (!g_license_thread) {
            SetEvent(g_stop_event);

            if (g_refresh_thread) {
                WaitForSingleObject(g_refresh_thread, 5000);
                CloseHandle(g_refresh_thread);
                g_refresh_thread = nullptr;
            }

            RpcMgmtStopServerListening(nullptr);
            WaitForSingleObject(rpc_thread, 5000);
            RpcServerUnregisterIf(WitcherControl_v1_0_s_ifspec, nullptr, FALSE);
            CloseHandle(rpc_thread);

            CloseHandle(g_stop_event);
            g_stop_event = nullptr;

            SetServiceStatusValue(SERVICE_STOPPED, GetLastError());

            witcher::FreeLicenseState();
            witcher::FreeAuthState();
            DeleteCriticalSection(&g_process_lock);
            return;
        }

        LaunchTrayAppsInExistingSessions();

        SetServiceStatusValue(SERVICE_RUNNING);

        WaitForSingleObject(g_stop_event, INFINITE);

        SetServiceStatusValue(SERVICE_STOP_PENDING, NO_ERROR, 5000);

        RpcMgmtStopServerListening(nullptr);
        WaitForSingleObject(rpc_thread, 5000);
        RpcServerUnregisterIf(WitcherControl_v1_0_s_ifspec, nullptr, FALSE);

        if (g_license_thread) {
            WaitForSingleObject(g_license_thread, 5000);
            CloseHandle(g_license_thread);
            g_license_thread = nullptr;
        }

        if (g_refresh_thread) {
            WaitForSingleObject(g_refresh_thread, 5000);
            CloseHandle(g_refresh_thread);
            g_refresh_thread = nullptr;
        }

        CloseHandle(rpc_thread);

        TerminateChildren();

        CloseHandle(g_stop_event);
        g_stop_event = nullptr;

        witcher::FreeLicenseState();
        witcher::FreeAuthState();
        DeleteCriticalSection(&g_process_lock);

        SetServiceStatusValue(SERVICE_STOPPED);
    }

    bool InstallService() {
        wchar_t module_path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, module_path, MAX_PATH);

        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) {
            return false;
        }

        SC_HANDLE service = CreateServiceW(
            scm,
            witcher::kServiceName,
            witcher::kServiceDisplayName,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            module_path,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (!service && GetLastError() == ERROR_SERVICE_EXISTS) {
            service = OpenServiceW(scm, witcher::kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_START);
        }

        if (service) {
            SERVICE_DESCRIPTIONW description{};
            description.lpDescription = const_cast<LPWSTR>(L"Starts and controls the Witcher tray application in user sessions.");
            ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);
            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
        return service != nullptr;
    }

    bool UninstallService() {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) {
            return false;
        }

        SC_HANDLE service = OpenServiceW(scm, witcher::kServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        const bool result = DeleteService(service) != FALSE;

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return result;
    }

}

extern "C" void RpcStopService(void) {
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
}

extern "C" long RpcLogin(const wchar_t* username, const wchar_t* password) {
    if (!username || !password) {
        return ERROR_INVALID_PARAMETER;
    }

    witcher::LoginResult loginResult =
        witcher::LoginRequest(username, password);

    if (!loginResult.success) {
        witcher::ClearLicenseTicket();
        witcher::ClearAuthTokens();
        return loginResult.errorCode;
    }

    long long accessExpiresAtUnix = 0;
    long long refreshExpiresAtUnix = 0;

    witcher::GetJwtExpirationUnix(
        loginResult.accessToken,
        &accessExpiresAtUnix
    );

    witcher::GetJwtExpirationUnix(
        loginResult.refreshToken,
        &refreshExpiresAtUnix
    );

    witcher::SetAuthTokens(
        loginResult.username,
        loginResult.accessToken,
        loginResult.refreshToken,
        accessExpiresAtUnix,
        refreshExpiresAtUnix
    );

    return ERROR_SUCCESS;
}

extern "C" long RpcLogout(void) {
    witcher::ClearLicenseTicket();
    witcher::ClearAuthTokens();
    return ERROR_SUCCESS;
}

extern "C" long RpcGetCurrentUser(
    long* isAuthenticated,
    wchar_t* usernameBuffer,
    unsigned long usernameCapacity
) {
    if (!isAuthenticated || !usernameBuffer || usernameCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    *isAuthenticated = 0;
    usernameBuffer[0] = L'\0';

    if (!witcher::IsAuthenticated()) {
        return ERROR_SUCCESS;
    }

    std::wstring username = witcher::GetAuthenticatedUsername();

    *isAuthenticated = 1;

    if (!CopyStringToRpcBuffer(username, usernameBuffer, usernameCapacity)) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

extern "C" long RpcCheckLicense(
    const wchar_t* licenseCode,
    const wchar_t* macAddress,
    const wchar_t* productId
) {
    if (!licenseCode || !macAddress || !productId) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!witcher::IsAuthenticated()) {
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    std::string accessToken = witcher::GetAccessToken();

    if (accessToken.empty()) {
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string licenseCodeUtf8 = WideToUtf8(licenseCode);
    const std::string macAddressUtf8 = WideToUtf8(macAddress);
    const std::string productIdUtf8 = WideToUtf8(productId);

    witcher::LicenseCheckResult licenseResult =
        witcher::CheckLicenseRequest(
            accessToken,
            licenseCodeUtf8,
            macAddressUtf8,
            productIdUtf8
        );

    if (!licenseResult.success) {
        witcher::ClearLicenseTicket();
        return licenseResult.errorCode;
    }

    StoreLicenseTicket(
        licenseResult.licenseTicket,
        licenseCodeUtf8,
        macAddressUtf8,
        productIdUtf8
    );

    return ERROR_SUCCESS;
}

extern "C" long RpcActivateLicense(
    const wchar_t* licenseCode,
    const wchar_t* macAddress,
    const wchar_t* productId
) {
    if (!licenseCode || !macAddress || !productId) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!witcher::IsAuthenticated()) {
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    std::string accessToken = witcher::GetAccessToken();

    if (accessToken.empty()) {
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string licenseCodeUtf8 = WideToUtf8(licenseCode);
    const std::string macAddressUtf8 = WideToUtf8(macAddress);
    const std::string productIdUtf8 = WideToUtf8(productId);

    witcher::LicenseActivateResult activateResult =
        witcher::ActivateLicenseRequest(
            accessToken,
            licenseCodeUtf8,
            macAddressUtf8,
            productIdUtf8
        );

    if (!activateResult.success) {
        witcher::ClearLicenseTicket();
        return activateResult.errorCode;
    }

    if (!activateResult.licenseTicket.empty()) {
        StoreLicenseTicket(
            activateResult.licenseTicket,
            licenseCodeUtf8,
            macAddressUtf8,
            productIdUtf8
        );

        return ERROR_SUCCESS;
    }

    witcher::LicenseCheckResult checkResult =
        witcher::CheckLicenseRequest(
            accessToken,
            licenseCodeUtf8,
            macAddressUtf8,
            productIdUtf8
        );

    if (!checkResult.success) {
        witcher::ClearLicenseTicket();
        return checkResult.errorCode;
    }

    StoreLicenseTicket(
        checkResult.licenseTicket,
        licenseCodeUtf8,
        macAddressUtf8,
        productIdUtf8
    );

    return ERROR_SUCCESS;
}

extern "C" long RpcGetLicenseInfo(
    long* hasLicense,
    wchar_t* expirationDateBuffer,
    unsigned long expirationDateCapacity
) {
    if (!hasLicense || !expirationDateBuffer || expirationDateCapacity == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    *hasLicense = 0;
    expirationDateBuffer[0] = L'\0';

    std::string expirationDateUtf8;

    if (!witcher::GetLicensePublicInfo(&expirationDateUtf8)) {
        return ERROR_SUCCESS;
    }

    *hasLicense = 1;

    std::wstring expirationDate = Utf8ToWide(expirationDateUtf8);

    if (!CopyStringToRpcBuffer(
        expirationDate,
        expirationDateBuffer,
        expirationDateCapacity
    )) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

extern "C" long RpcGetAntivirusStatus(long* isEnabled) {
    if (!isEnabled) {
        return ERROR_INVALID_PARAMETER;
    }

    *isEnabled = 0;

    if (!witcher::HasLicenseTicket()) {
        return witcher::kErrorNoLicense;
    }

    *isEnabled = 1;
    return ERROR_SUCCESS;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    HeapFree(GetProcessHeap(), 0, pointer);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        const std::wstring arg = argv[1];

        if (arg == L"--install") {
            return InstallService() ? 0 : 1;
        }

        if (arg == L"--uninstall") {
            return UninstallService() ? 0 : 1;
        }
    }

    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(witcher::kServiceName), ServiceMain},
        {nullptr, nullptr}
    };

    return StartServiceCtrlDispatcherW(service_table) ? 0 : 1;
}