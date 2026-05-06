#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "common.h"
#include "WitcherControl_h.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace {

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
CRITICAL_SECTION g_process_lock;
std::vector<PROCESS_INFORMATION> g_children;

void SetServiceStatusValue(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_SESSIONCHANGE : 0;
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
    if (!DuplicateTokenEx(user_token,
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

    auto app_path = GetModuleDirectory() / witcher::kTrayAppExeName;
    std::wstring command_line = L"\"" + app_path.wstring() + L"\" --hidden --service-child";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION process{};
    DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT;
    BOOL created = CreateProcessAsUserW(primary_token,
                                        app_path.c_str(),
                                        command_line.data(),
                                        nullptr,
                                        nullptr,
                                        FALSE,
                                        creation_flags,
                                        environment,
                                        GetModuleDirectory().c_str(),
                                        &startup,
                                        &process);

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
            (session.State == WTSActive || session.State == WTSConnected || session.State == WTSDisconnected)) {
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

DWORD WINAPI RpcServerThread(void*) {
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(witcher::kRpcEndpoint)),
        nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        SetEvent(g_stop_event);
        return status;
    }

    status = RpcServerRegisterIf2(WitcherControl_v1_0_s_ifspec,
                                  nullptr,
                                  nullptr,
                                  RPC_IF_ALLOW_LOCAL_ONLY,
                                  RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                  static_cast<unsigned>(-1),
                                  nullptr);
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
        if (event_type == WTS_SESSION_LOGON || event_type == WTS_SESSION_UNLOCK || event_type == WTS_CONSOLE_CONNECT ||
            event_type == WTS_REMOTE_CONNECT) {
            auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(event_data);
            if (notification && notification->dwSessionId != 0) {
                LaunchTrayAppInSession(notification->dwSessionId);
            }
        }
        return NO_ERROR;
    }

    // Stop and shutdown are intentionally not accepted by dwControlsAccepted.
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(witcher::kServiceName, ServiceControlHandlerEx, nullptr);
    if (!g_status_handle) {
        return;
    }

    SetServiceStatusValue(SERVICE_START_PENDING, NO_ERROR, 3000);

    InitializeCriticalSection(&g_process_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        SetServiceStatusValue(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    HANDLE rpc_thread = CreateThread(nullptr, 0, RpcServerThread, nullptr, 0, nullptr);
    if (!rpc_thread) {
        CloseHandle(g_stop_event);
        SetServiceStatusValue(SERVICE_STOPPED, GetLastError());
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
    CloseHandle(rpc_thread);

    TerminateChildren();
    CloseHandle(g_stop_event);
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

    SC_HANDLE service = CreateServiceW(scm,
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
                                       nullptr);
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

} // namespace

extern "C" void RpcStopService(void) {
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
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
