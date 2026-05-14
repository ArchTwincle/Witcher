#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <aclapi.h>
#include <sddl.h>

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
#include "av_engine.h"

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

    void SetServiceStatusValue(
        DWORD state,
        DWORD win32_exit_code = NO_ERROR,
        DWORD wait_hint = 0
    ) {
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

    bool GetActiveUserSessionId(DWORD* session_id) {
        if (!session_id) {
            return false;
        }

        *session_id = 0;

        WTS_SESSION_INFOW* sessions = nullptr;
        DWORD count = 0;

        if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
            for (DWORD i = 0; i < count; ++i) {
                if (sessions[i].SessionId != 0 && sessions[i].State == WTSActive) {
                    *session_id = sessions[i].SessionId;
                    WTSFreeMemory(sessions);
                    return true;
                }
            }

            WTSFreeMemory(sessions);
        }

        DWORD console_session_id = WTSGetActiveConsoleSessionId();

        if (console_session_id != 0xFFFFFFFF && console_session_id != 0) {
            *session_id = console_session_id;
            return true;
        }

        return false;
    }

    bool ConfigureProcessDacl(HANDLE process_handle) {
        if (!process_handle) {
            return false;
        }

        constexpr DWORD kLimitedProcessReadRights =
            PROCESS_QUERY_LIMITED_INFORMATION |
            SYNCHRONIZE;

        EXPLICIT_ACCESSW entries[7]{};

        entries[0].grfAccessPermissions = PROCESS_TERMINATE;
        entries[0].grfAccessMode = DENY_ACCESS;
        entries[0].grfInheritance = NO_INHERITANCE;
        entries[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[0].Trustee.ptstrName = const_cast<LPWSTR>(L"BUILTIN\\Administrators");

        entries[1].grfAccessPermissions = PROCESS_TERMINATE;
        entries[1].grfAccessMode = DENY_ACCESS;
        entries[1].grfInheritance = NO_INHERITANCE;
        entries[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[1].Trustee.ptstrName = const_cast<LPWSTR>(L"BUILTIN\\Users");

        entries[2].grfAccessPermissions = PROCESS_TERMINATE;
        entries[2].grfAccessMode = DENY_ACCESS;
        entries[2].grfInheritance = NO_INHERITANCE;
        entries[2].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[2].Trustee.ptstrName = const_cast<LPWSTR>(L"NT AUTHORITY\\Authenticated Users");

        entries[3].grfAccessPermissions = PROCESS_ALL_ACCESS;
        entries[3].grfAccessMode = SET_ACCESS;
        entries[3].grfInheritance = NO_INHERITANCE;
        entries[3].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[3].Trustee.TrusteeType = TRUSTEE_IS_USER;
        entries[3].Trustee.ptstrName = const_cast<LPWSTR>(L"NT AUTHORITY\\SYSTEM");

        entries[4].grfAccessPermissions = kLimitedProcessReadRights;
        entries[4].grfAccessMode = SET_ACCESS;
        entries[4].grfInheritance = NO_INHERITANCE;
        entries[4].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[4].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[4].Trustee.ptstrName = const_cast<LPWSTR>(L"BUILTIN\\Administrators");

        entries[5].grfAccessPermissions = kLimitedProcessReadRights;
        entries[5].grfAccessMode = SET_ACCESS;
        entries[5].grfInheritance = NO_INHERITANCE;
        entries[5].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[5].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[5].Trustee.ptstrName = const_cast<LPWSTR>(L"BUILTIN\\Users");

        entries[6].grfAccessPermissions = kLimitedProcessReadRights;
        entries[6].grfAccessMode = SET_ACCESS;
        entries[6].grfInheritance = NO_INHERITANCE;
        entries[6].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        entries[6].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        entries[6].Trustee.ptstrName = const_cast<LPWSTR>(L"NT AUTHORITY\\Authenticated Users");

        PACL new_dacl = nullptr;

        DWORD result = SetEntriesInAclW(
            static_cast<ULONG>(_countof(entries)),
            entries,
            nullptr,
            &new_dacl
        );

        if (result != ERROR_SUCCESS || !new_dacl) {
            return false;
        }

        result = SetSecurityInfo(
            process_handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            new_dacl,
            nullptr
        );

        LocalFree(new_dacl);
        return result == ERROR_SUCCESS;
    }

    bool ConfigureCurrentProcessDacl() {
        HANDLE process_handle = OpenProcess(
            WRITE_DAC | READ_CONTROL,
            FALSE,
            GetCurrentProcessId()
        );

        if (!process_handle) {
            return false;
        }

        bool result = ConfigureProcessDacl(process_handle);
        CloseHandle(process_handle);
        return result;
    }

    bool ConfigureChildProcessDacl(HANDLE child_process_handle) {
        return ConfigureProcessDacl(child_process_handle);
    }

    std::filesystem::path GetModuleDirectory() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        return std::filesystem::path(path).parent_path();
    }

    bool ConfirmServiceStopWithActiveUser() {
        DWORD active_session_id = 0;

        if (!GetActiveUserSessionId(&active_session_id)) {
            return false;
        }

        HANDLE user_token = nullptr;

        if (!WTSQueryUserToken(active_session_id, &user_token)) {
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
            &primary_token
        )) {
            CloseHandle(user_token);
            return false;
        }

        CloseHandle(user_token);

        void* environment = nullptr;
        CreateEnvironmentBlock(&environment, primary_token, FALSE);

        const auto module_directory = GetModuleDirectory();
        const auto app_path = module_directory / witcher::kTrayAppExeName;

        std::wstring command_line =
            L"\"" + app_path.wstring() + L"\" --secure-stop-confirm";

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

        PROCESS_INFORMATION process{};

        BOOL created = CreateProcessAsUserW(
            primary_token,
            app_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_UNICODE_ENVIRONMENT,
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

        DWORD wait_result = WaitForSingleObject(process.hProcess, 30000);

        if (wait_result == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, 3000);
        }

        DWORD exit_code = 1;
        GetExitCodeProcess(process.hProcess, &exit_code);

        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);

        return exit_code == 0;
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

        size_t key_pos = json.find(pattern);
        if (key_pos == std::string::npos) {
            return 0;
        }

        size_t colon_pos = json.find(':', key_pos);
        if (colon_pos == std::string::npos) {
            return 0;
        }

        size_t number_start = json.find_first_of("0123456789", colon_pos + 1);
        if (number_start == std::string::npos) {
            return 0;
        }

        size_t number_end = json.find_first_not_of("0123456789", number_start);

        try {
            return std::stoll(json.substr(number_start, number_end - number_start));
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

        size_t key_pos = json.find(pattern);
        if (key_pos == std::string::npos) {
            return {};
        }

        size_t colon_pos = json.find(':', key_pos);
        if (colon_pos == std::string::npos) {
            return {};
        }

        size_t first_quote = json.find('"', colon_pos + 1);
        if (first_quote == std::string::npos) {
            return {};
        }

        size_t second_quote = json.find('"', first_quote + 1);
        if (second_quote == std::string::npos) {
            return {};
        }

        return json.substr(first_quote + 1, second_quote - first_quote - 1);
    }

    void StoreLicenseTicket(
        const std::string& license_ticket,
        const std::string& license_code,
        const std::string& mac_address,
        const std::string& product_id
    ) {
        long long ticket_lifetime_seconds = ExtractJsonNumber(
            license_ticket,
            "ticketLifetimeSeconds"
        );

        std::string expiration_date = ExtractJsonString(
            license_ticket,
            "expirationDate"
        );

        witcher::SetLicenseTicket(
            license_ticket,
            ticket_lifetime_seconds,
            expiration_date,
            license_code,
            mac_address,
            product_id
        );
    }

    bool CopyStringToRpcBuffer(
        const std::wstring& source,
        wchar_t* destination,
        unsigned long destination_capacity
    ) {
        if (!destination || destination_capacity == 0) {
            return false;
        }

        destination[0] = L'\0';

        if (source.empty()) {
            return true;
        }

        wcsncpy_s(
            destination,
            destination_capacity,
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
            &primary_token
        )) {
            CloseHandle(user_token);
            return false;
        }

        CloseHandle(user_token);

        void* environment = nullptr;
        CreateEnvironmentBlock(&environment, primary_token, FALSE);

        const auto module_directory = GetModuleDirectory();
        const auto app_path = module_directory / witcher::kTrayAppExeName;

        std::wstring command_line =
            L"\"" + app_path.wstring() + L"\" --hidden --service-child";

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

        PROCESS_INFORMATION process{};

        BOOL created = CreateProcessAsUserW(
            primary_token,
            app_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_UNICODE_ENVIRONMENT,
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

        ConfigureChildProcessDacl(process.hProcess);

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
                if (WaitForSingleObject(g_stop_event, 5000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long access_expires_at_unix = 0;
            long long refresh_expires_at_unix = 0;

            if (!witcher::GetTokenExpirations(
                &access_expires_at_unix,
                &refresh_expires_at_unix
            )) {
                if (WaitForSingleObject(g_stop_event, 5000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            const long long now_unix = static_cast<long long>(std::time(nullptr));

            if (refresh_expires_at_unix > 0 && now_unix >= refresh_expires_at_unix) {
                witcher_av::ClearDatabase();
                witcher::ClearLicenseTicket();
                witcher::ClearAuthTokens();

                if (WaitForSingleObject(g_stop_event, 5000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long seconds_until_refresh = 60;

            if (access_expires_at_unix > 0) {
                seconds_until_refresh = access_expires_at_unix - now_unix - 60;
            }

            if (seconds_until_refresh < 5) {
                seconds_until_refresh = 5;
            }

            DWORD wait_milliseconds = static_cast<DWORD>(seconds_until_refresh * 1000);
            DWORD wait_result = WaitForSingleObject(g_stop_event, wait_milliseconds);

            if (wait_result == WAIT_OBJECT_0) {
                break;
            }

            if (!witcher::IsAuthenticated()) {
                continue;
            }

            std::string current_refresh_token = witcher::GetRefreshToken();
            std::wstring current_username = witcher::GetAuthenticatedUsername();

            if (current_refresh_token.empty()) {
                witcher_av::ClearDatabase();
                witcher::ClearLicenseTicket();
                witcher::ClearAuthTokens();
                continue;
            }

            witcher::RefreshResult refresh_result =
                witcher::RefreshTokenRequest(current_refresh_token);

            if (!refresh_result.success) {
                if (WaitForSingleObject(g_stop_event, 30000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long new_access_expires_at_unix = 0;
            long long new_refresh_expires_at_unix = 0;

            witcher::GetJwtExpirationUnix(
                refresh_result.accessToken,
                &new_access_expires_at_unix
            );

            witcher::GetJwtExpirationUnix(
                refresh_result.refreshToken,
                &new_refresh_expires_at_unix
            );

            witcher::SetAuthTokens(
                current_username,
                refresh_result.accessToken,
                refresh_result.refreshToken,
                new_access_expires_at_unix,
                new_refresh_expires_at_unix
            );
        }

        return 0;
    }

    DWORD WINAPI LicenseRefreshThread(void*) {
        while (true) {
            if (!witcher::IsAuthenticated() || !witcher::HasLicenseTicket()) {
                if (WaitForSingleObject(g_stop_event, 5000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long ticket_saved_at_unix = 0;
            long long ticket_lifetime_seconds = 0;
            std::string license_code;
            std::string mac_address;
            std::string product_id;

            if (!witcher::GetLicenseRefreshRequestInfo(
                &ticket_saved_at_unix,
                &ticket_lifetime_seconds,
                &license_code,
                &mac_address,
                &product_id
            )) {
                witcher_av::ClearDatabase();
                witcher::ClearLicenseTicket();

                if (WaitForSingleObject(g_stop_event, 5000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            long long seconds_until_refresh = 60;

            if (ticket_lifetime_seconds > 0) {
                const long long now_unix = static_cast<long long>(std::time(nullptr));
                const long long refresh_at_unix =
                    ticket_saved_at_unix + ticket_lifetime_seconds - 60;

                seconds_until_refresh = refresh_at_unix - now_unix;
            }

            if (seconds_until_refresh < 5) {
                seconds_until_refresh = 5;
            }

            DWORD wait_milliseconds = static_cast<DWORD>(seconds_until_refresh * 1000);
            DWORD wait_result = WaitForSingleObject(g_stop_event, wait_milliseconds);

            if (wait_result == WAIT_OBJECT_0) {
                break;
            }

            if (!witcher::IsAuthenticated()) {
                witcher_av::ClearDatabase();
                witcher::ClearLicenseTicket();
                continue;
            }

            std::string access_token = witcher::GetAccessToken();

            if (access_token.empty()) {
                witcher_av::ClearDatabase();
                witcher::ClearLicenseTicket();
                continue;
            }

            witcher::LicenseCheckResult license_result =
                witcher::CheckLicenseRequest(
                    access_token,
                    license_code,
                    mac_address,
                    product_id
                );

            if (!license_result.success) {
                if (WaitForSingleObject(g_stop_event, 30000) == WAIT_OBJECT_0) {
                    break;
                }

                continue;
            }

            StoreLicenseTicket(
                license_result.licenseTicket,
                license_code,
                mac_address,
                product_id
            );

            witcher_av::LoadDefaultDatabase();
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

    DWORD WINAPI ServiceControlHandlerEx(
        DWORD control,
        DWORD event_type,
        void* event_data,
        void*
    ) {
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

        ConfigureCurrentProcessDacl();

        InitializeCriticalSection(&g_process_lock);
        witcher::InitAuthState();
        witcher::InitLicenseState();
        witcher_av::InitializeAvEngine();

        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        if (!g_stop_event) {
            SetServiceStatusValue(SERVICE_STOPPED, GetLastError());
            witcher_av::FreeAvEngine();
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
            witcher_av::FreeAvEngine();
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

            witcher_av::FreeAvEngine();
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

            witcher_av::FreeAvEngine();
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

        witcher_av::FreeAvEngine();
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
            service = OpenServiceW(
                scm,
                witcher::kServiceName,
                SERVICE_CHANGE_CONFIG | SERVICE_START
            );
        }

        if (service) {
            SERVICE_DESCRIPTIONW description{};
            description.lpDescription =
                const_cast<LPWSTR>(L"Starts and controls the Witcher tray application in user sessions.");
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

        SC_HANDLE service = OpenServiceW(
            scm,
            witcher::kServiceName,
            DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS
        );

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
    if (!g_stop_event) {
        return;
    }

    if (!ConfirmServiceStopWithActiveUser()) {
        return;
    }

    SetEvent(g_stop_event);
}

extern "C" long RpcLogin(const wchar_t* username, const wchar_t* password) {
    if (!username || !password) {
        return ERROR_INVALID_PARAMETER;
    }

    witcher::LoginResult login_result =
        witcher::LoginRequest(username, password);

    if (!login_result.success) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        witcher::ClearAuthTokens();
        return login_result.errorCode;
    }

    long long access_expires_at_unix = 0;
    long long refresh_expires_at_unix = 0;

    witcher::GetJwtExpirationUnix(
        login_result.accessToken,
        &access_expires_at_unix
    );

    witcher::GetJwtExpirationUnix(
        login_result.refreshToken,
        &refresh_expires_at_unix
    );

    witcher::SetAuthTokens(
        login_result.username,
        login_result.accessToken,
        login_result.refreshToken,
        access_expires_at_unix,
        refresh_expires_at_unix
    );

    return ERROR_SUCCESS;
}

extern "C" long RpcLogout(void) {
    witcher_av::ClearDatabase();
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
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    std::string access_token = witcher::GetAccessToken();

    if (access_token.empty()) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string license_code_utf8 = WideToUtf8(licenseCode);
    const std::string mac_address_utf8 = WideToUtf8(macAddress);
    const std::string product_id_utf8 = WideToUtf8(productId);

    witcher::LicenseCheckResult license_result =
        witcher::CheckLicenseRequest(
            access_token,
            license_code_utf8,
            mac_address_utf8,
            product_id_utf8
        );

    if (!license_result.success) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return license_result.errorCode;
    }

    StoreLicenseTicket(
        license_result.licenseTicket,
        license_code_utf8,
        mac_address_utf8,
        product_id_utf8
    );

    witcher_av::LoadDefaultDatabase();

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
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    std::string access_token = witcher::GetAccessToken();

    if (access_token.empty()) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    const std::string license_code_utf8 = WideToUtf8(licenseCode);
    const std::string mac_address_utf8 = WideToUtf8(macAddress);
    const std::string product_id_utf8 = WideToUtf8(productId);

    witcher::LicenseActivateResult activate_result =
        witcher::ActivateLicenseRequest(
            access_token,
            license_code_utf8,
            mac_address_utf8,
            product_id_utf8
        );

    if (!activate_result.success) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return activate_result.errorCode;
    }

    if (!activate_result.licenseTicket.empty()) {
        StoreLicenseTicket(
            activate_result.licenseTicket,
            license_code_utf8,
            mac_address_utf8,
            product_id_utf8
        );

        witcher_av::LoadDefaultDatabase();

        return ERROR_SUCCESS;
    }

    witcher::LicenseCheckResult check_result =
        witcher::CheckLicenseRequest(
            access_token,
            license_code_utf8,
            mac_address_utf8,
            product_id_utf8
        );

    if (!check_result.success) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return check_result.errorCode;
    }

    StoreLicenseTicket(
        check_result.licenseTicket,
        license_code_utf8,
        mac_address_utf8,
        product_id_utf8
    );

    witcher_av::LoadDefaultDatabase();

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

    std::string expiration_date_utf8;

    if (!witcher::GetLicensePublicInfo(&expiration_date_utf8)) {
        return ERROR_SUCCESS;
    }

    *hasLicense = 1;

    std::wstring expiration_date = Utf8ToWide(expiration_date_utf8);

    if (!CopyStringToRpcBuffer(
        expiration_date,
        expirationDateBuffer,
        expirationDateCapacity
    )) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

extern "C" long RpcRefreshLicenseStatus(void) {
    if (!witcher::IsAuthenticated()) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    std::string access_token = witcher::GetAccessToken();

    if (access_token.empty()) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return ERROR_NOT_LOGGED_ON;
    }

    long long ticket_saved_at_unix = 0;
    long long ticket_lifetime_seconds = 0;
    std::string license_code;
    std::string mac_address;
    std::string product_id;

    if (!witcher::GetLicenseRefreshRequestInfo(
        &ticket_saved_at_unix,
        &ticket_lifetime_seconds,
        &license_code,
        &mac_address,
        &product_id
    )) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return witcher::kErrorNoLicense;
    }

    witcher::LicenseCheckResult license_result =
        witcher::CheckLicenseRequest(
            access_token,
            license_code,
            mac_address,
            product_id
        );

    if (!license_result.success) {
        witcher_av::ClearDatabase();
        witcher::ClearLicenseTicket();
        return license_result.errorCode;
    }

    StoreLicenseTicket(
        license_result.licenseTicket,
        license_code,
        mac_address,
        product_id
    );

    witcher_av::LoadDefaultDatabase();

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

extern "C" long RpcGetAvDatabaseInfo(
    long* isLoaded,
    wchar_t* releaseDateBuffer,
    unsigned long releaseDateCapacity,
    unsigned long long* recordCount
) {
    if (!isLoaded || !releaseDateBuffer || releaseDateCapacity == 0 || !recordCount) {
        return ERROR_INVALID_PARAMETER;
    }

    *isLoaded = 0;
    *recordCount = 0;
    releaseDateBuffer[0] = L'\0';

    if (!witcher::HasLicenseTicket()) {
        return witcher::kErrorNoLicense;
    }

    witcher_av::AvDatabaseInfo info = witcher_av::GetDatabaseInfo();

    *isLoaded = info.loaded ? 1 : 0;
    *recordCount = info.recordCount;

    if (!CopyStringToRpcBuffer(
        info.releaseDate,
        releaseDateBuffer,
        releaseDateCapacity
    )) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

extern "C" long RpcScanFile(
    const wchar_t* filePath,
    long* isMalicious,
    wchar_t* threatNameBuffer,
    unsigned long threatNameCapacity,
    unsigned long long* scannedFiles,
    unsigned long long* maliciousFiles
) {
    if (!filePath || !isMalicious || !threatNameBuffer ||
        threatNameCapacity == 0 || !scannedFiles || !maliciousFiles) {
        return ERROR_INVALID_PARAMETER;
    }

    *isMalicious = 0;
    *scannedFiles = 0;
    *maliciousFiles = 0;
    threatNameBuffer[0] = L'\0';

    if (!witcher::HasLicenseTicket()) {
        return witcher::kErrorNoLicense;
    }

    if (!witcher_av::IsDatabaseLoaded()) {
        witcher_av::LoadDefaultDatabase();
    }

    witcher_av::ScanResult result{};

    if (!witcher_av::ScanFile(filePath, &result)) {
        return ERROR_FILE_NOT_FOUND;
    }

    *isMalicious = result.malicious ? 1 : 0;
    *scannedFiles = result.scannedFiles;
    *maliciousFiles = result.maliciousFiles;

    if (!CopyStringToRpcBuffer(
        result.threatName,
        threatNameBuffer,
        threatNameCapacity
    )) {
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

extern "C" long RpcScanDirectory(
    const wchar_t* directoryPath,
    long* isMalicious,
    wchar_t* threatNameBuffer,
    unsigned long threatNameCapacity,
    unsigned long long* scannedFiles,
    unsigned long long* maliciousFiles
) {
    if (!directoryPath || !isMalicious || !threatNameBuffer ||
        threatNameCapacity == 0 || !scannedFiles || !maliciousFiles) {
        return ERROR_INVALID_PARAMETER;
    }

    *isMalicious = 0;
    *scannedFiles = 0;
    *maliciousFiles = 0;
    threatNameBuffer[0] = L'\0';

    if (!witcher::HasLicenseTicket()) {
        return witcher::kErrorNoLicense;
    }

    if (!witcher_av::IsDatabaseLoaded()) {
        witcher_av::LoadDefaultDatabase();
    }

    witcher_av::ScanResult result{};

    if (!witcher_av::ScanDirectory(directoryPath, &result)) {
        return ERROR_PATH_NOT_FOUND;
    }

    *isMalicious = result.malicious ? 1 : 0;
    *scannedFiles = result.scannedFiles;
    *maliciousFiles = result.maliciousFiles;

    if (!CopyStringToRpcBuffer(
        result.threatName,
        threatNameBuffer,
        threatNameCapacity
    )) {
        return ERROR_INVALID_PARAMETER;
    }

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
        { const_cast<LPWSTR>(witcher::kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(service_table) ? 0 : 1;
}