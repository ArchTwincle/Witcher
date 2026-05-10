#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>

#include <algorithm>
#include <string>
#include <vector>

#include "../resources/resource.h"
#include "common.h"
#include "WitcherControl_h.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

handle_t WitcherControl_IfHandle = nullptr;

namespace {

    constexpr wchar_t kWindowClassName[] = L"TourismServiceTrayWindowClass";
    constexpr wchar_t kWindowTitle[] = L"Tourism Service Tray App";
    constexpr wchar_t kMutexName[] = L"Local\\TourismServiceTrayApp.SingleInstance";

    constexpr UINT kTrayCallbackMessage = WM_APP + 1;
    constexpr UINT_PTR kTrayIconId = 1;

    constexpr UINT kMenuOpen = 1001;
    constexpr UINT kMenuExit = 1002;

    constexpr int kControlUsernameEdit = 2001;
    constexpr int kControlPasswordEdit = 2002;
    constexpr int kControlLoginButton = 2003;
    constexpr int kControlLicenseCodeEdit = 2004;
    constexpr int kControlActivateButton = 2005;
    constexpr int kControlLogoutButton = 2006;
    constexpr int kControlRefreshButton = 2007;

    constexpr UINT_PTR kLicensePollTimerId = 3001;
    constexpr UINT kLicensePollIntervalMs = 30000;

    constexpr wchar_t kProductId[] = L"7a11219b-2bdd-4475-a9fb-c535ce20650d";
    constexpr wchar_t kMacAddress[] = L"AA-BB-CC-DD-EE-FF";

    enum class UiState {
        Login,
        Activation,
        Main
    };

    HINSTANCE g_instance = nullptr;
    HWND g_main_window = nullptr;
    NOTIFYICONDATAW g_tray_icon{};
    UINT g_taskbar_created_message = 0;
    HANDLE g_single_instance_mutex = nullptr;
    bool g_is_exiting = false;

    UiState g_ui_state = UiState::Login;
    bool g_is_authenticated = false;
    bool g_has_license = false;

    std::wstring g_username;
    std::wstring g_license_expiration_date;
    std::wstring g_last_error_text;

    std::vector<HWND> g_child_controls;

    std::wstring ToLower(std::wstring text) {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(towlower(ch));
        });

        return text;
    }

    bool HasArgument(const wchar_t* expected) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        if (!argv) {
            return false;
        }

        bool found = false;

        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argv[i], expected) == 0) {
                found = true;
                break;
            }
        }

        LocalFree(argv);
        return found;
    }

    int RunSecureStopConfirmation() {
        HDESK original_desktop = OpenInputDesktop(
            0,
            FALSE,
            DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS
        );

        HDESK confirm_desktop = CreateDesktopW(
            L"WitcherStopConfirmationDesktop",
            nullptr,
            nullptr,
            0,
            GENERIC_ALL,
            nullptr
        );

        if (!confirm_desktop) {
            int fallback_result = MessageBoxW(
                nullptr,
                L"Stop WitcherTrayService and close all tray applications?",
                L"WitcherTrayService",
                MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND
            );

            if (original_desktop) {
                CloseDesktop(original_desktop);
            }

            return fallback_result == IDYES ? 0 : 1;
        }

        bool switched_to_confirm = SwitchDesktop(confirm_desktop) != FALSE;
        bool thread_desktop_set = SetThreadDesktop(confirm_desktop) != FALSE;

        int result = IDNO;

        if (switched_to_confirm && thread_desktop_set) {
            result = MessageBoxW(
                nullptr,
                L"Stop WitcherTrayService and close all tray applications?",
                L"WitcherTrayService",
                MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND
            );
        }

        if (original_desktop) {
            SwitchDesktop(original_desktop);
        }

        CloseDesktop(confirm_desktop);

        if (original_desktop) {
            CloseDesktop(original_desktop);
        }

        if (!switched_to_confirm || !thread_desktop_set) {
            return 1;
        }

        return result == IDYES ? 0 : 1;
    }

    bool HasHiddenStartupArgument() {
        return HasArgument(L"--hidden") ||
            HasArgument(L"--no-window") ||
            HasArgument(L"/hidden");
    }

    bool QueryServiceState(DWORD* state) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);

        if (!scm) {
            return false;
        }

        SC_HANDLE service = OpenServiceW(
            scm,
            witcher::kServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START
        );

        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytes_needed = 0;

        const BOOL ok = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed
        );

        if (ok && state) {
            *state = status.dwCurrentState;
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return ok != FALSE;
    }

    bool StartServiceAndWaitRunning() {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);

        if (!scm) {
            return false;
        }

        SC_HANDLE service = OpenServiceW(
            scm,
            witcher::kServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START
        );

        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytes_needed = 0;

        if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed
        )) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        if (status.dwCurrentState == SERVICE_STOPPED) {
            StartServiceW(service, 0, nullptr);
        }

        bool running = false;

        for (int i = 0; i < 50; ++i) {
            if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &bytes_needed
            )) {
                break;
            }

            if (status.dwCurrentState == SERVICE_RUNNING) {
                running = true;
                break;
            }

            Sleep(200);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return running;
    }

    bool IsServiceStopped() {
        DWORD state = 0;
        return QueryServiceState(&state) && state == SERVICE_STOPPED;
    }

    DWORD GetParentProcessId() {
        const DWORD current_pid = GetCurrentProcessId();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        DWORD parent_pid = 0;

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID == current_pid) {
                    parent_pid = entry.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        return parent_pid;
    }

    std::wstring GetProcessImageBaseName(DWORD pid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot == INVALID_HANDLE_VALUE) {
            return L"";
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        std::wstring name;

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID == pid) {
                    name = entry.szExeFile;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        return name;
    }

    bool IsParentServiceProcess() {
        const DWORD parent_pid = GetParentProcessId();

        if (parent_pid == 0) {
            return false;
        }

        const std::wstring parent_name = ToLower(GetProcessImageBaseName(parent_pid));
        return parent_name == ToLower(witcher::kServiceExeName);
    }

    bool ConnectRpc() {
        RPC_WSTR string_binding = nullptr;

        RPC_STATUS status = RpcStringBindingComposeW(
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
            nullptr,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(witcher::kRpcEndpoint)),
            nullptr,
            &string_binding
        );

        if (status != RPC_S_OK) {
            return false;
        }

        status = RpcBindingFromStringBindingW(
            string_binding,
            &WitcherControl_IfHandle
        );

        RpcStringFreeW(&string_binding);

        return status == RPC_S_OK;
    }

    void DisconnectRpc() {
        if (WitcherControl_IfHandle) {
            RpcBindingFree(&WitcherControl_IfHandle);
            WitcherControl_IfHandle = nullptr;
        }
    }

    std::wstring ErrorCodeToText(long error_code) {
        wchar_t buffer[128]{};
        wsprintfW(buffer, L"Code: %ld", error_code);
        return buffer;
    }

    std::wstring GetWindowTextString(HWND hwnd) {
        const int length = GetWindowTextLengthW(hwnd);

        if (length <= 0) {
            return L"";
        }

        std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
        GetWindowTextW(hwnd, buffer.data(), static_cast<int>(buffer.size()));

        return std::wstring(buffer.data());
    }

    void ClearChildControls() {
        for (HWND control : g_child_controls) {
            if (control) {
                DestroyWindow(control);
            }
        }

        g_child_controls.clear();
    }

    HWND AddStaticText(
        HWND parent,
        const wchar_t* text,
        int x,
        int y,
        int width,
        int height
    ) {
        HWND control = CreateWindowExW(
            0,
            L"STATIC",
            text,
            WS_CHILD | WS_VISIBLE,
            x,
            y,
            width,
            height,
            parent,
            nullptr,
            g_instance,
            nullptr
        );

        if (control) {
            g_child_controls.push_back(control);
        }

        return control;
    }

    HWND AddEdit(
        HWND parent,
        int id,
        int x,
        int y,
        int width,
        int height,
        bool password = false
    ) {
        DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;

        if (password) {
            style |= ES_PASSWORD;
        }

        HWND control = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            L"",
            style,
            x,
            y,
            width,
            height,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            g_instance,
            nullptr
        );

        if (control) {
            g_child_controls.push_back(control);
        }

        return control;
    }

    HWND AddButton(
        HWND parent,
        int id,
        const wchar_t* text,
        int x,
        int y,
        int width,
        int height
    ) {
        HWND control = CreateWindowExW(
            0,
            L"BUTTON",
            text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            x,
            y,
            width,
            height,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            g_instance,
            nullptr
        );

        if (control) {
            g_child_controls.push_back(control);
        }

        return control;
    }

    bool RpcGetCurrentUserSafe() {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long is_authenticated = 0;
        wchar_t username_buffer[256]{};

        long result = RpcGetCurrentUser(
            &is_authenticated,
            username_buffer,
            static_cast<unsigned long>(_countof(username_buffer))
        );

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"RpcGetCurrentUser failed. " + ErrorCodeToText(result);
            return false;
        }

        g_is_authenticated = is_authenticated != 0;
        g_username = username_buffer;
        return true;
    }

    bool RpcGetLicenseInfoSafe() {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long has_license = 0;
        wchar_t expiration_date_buffer[256]{};

        long result = RpcGetLicenseInfo(
            &has_license,
            expiration_date_buffer,
            static_cast<unsigned long>(_countof(expiration_date_buffer))
        );

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"RpcGetLicenseInfo failed. " + ErrorCodeToText(result);
            return false;
        }

        g_has_license = has_license != 0;
        g_license_expiration_date = expiration_date_buffer;
        return true;
    }

    bool RpcLoginSafe(
        const std::wstring& username,
        const std::wstring& password
    ) {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long result = RpcLogin(username.c_str(), password.c_str());

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"Login failed. " + ErrorCodeToText(result);
            return false;
        }

        g_last_error_text.clear();
        return true;
    }

    bool RpcLogoutSafe() {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long result = RpcLogout();

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"Logout failed. " + ErrorCodeToText(result);
            return false;
        }

        g_last_error_text.clear();
        return true;
    }

    bool RpcCheckLicenseSafe(
        const std::wstring& license_code
    ) {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long result = RpcCheckLicense(
            license_code.c_str(),
            kMacAddress,
            kProductId
        );

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"License check failed. " + ErrorCodeToText(result);
            return false;
        }

        g_last_error_text.clear();
        return true;
    }

    bool RpcActivateLicenseSafe(
        const std::wstring& license_code
    ) {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            return false;
        }

        long result = RpcActivateLicense(
            license_code.c_str(),
            kMacAddress,
            kProductId
        );

        DisconnectRpc();

        if (result != ERROR_SUCCESS) {
            g_last_error_text = L"License activation failed. " + ErrorCodeToText(result);
            return false;
        }

        g_last_error_text.clear();
        return true;
    }

    void RefreshApplicationState();

    void BuildLoginView(HWND hwnd) {
        ClearChildControls();

        AddStaticText(hwnd, L"Authentication required", 40, 35, 300, 24);
        AddStaticText(hwnd, L"Username:", 40, 90, 120, 24);
        AddStaticText(hwnd, L"Password:", 40, 135, 120, 24);

        HWND username_edit = AddEdit(hwnd, kControlUsernameEdit, 165, 86, 250, 28);
        HWND password_edit = AddEdit(hwnd, kControlPasswordEdit, 165, 131, 250, 28, true);

        SetWindowTextW(username_edit, L"admin");
        SetWindowTextW(password_edit, L"Admin123!");

        AddButton(hwnd, kControlLoginButton, L"Login", 165, 180, 120, 32);

        if (!g_last_error_text.empty()) {
            AddStaticText(hwnd, g_last_error_text.c_str(), 40, 235, 540, 28);
        }

        InvalidateRect(hwnd, nullptr, TRUE);
    }

    void BuildActivationView(HWND hwnd) {
        ClearChildControls();

        std::wstring title = L"User: " + g_username;

        AddStaticText(hwnd, title.c_str(), 40, 35, 500, 24);
        AddStaticText(hwnd, L"No active license. Antivirus functionality is blocked.", 40, 75, 540, 24);
        AddStaticText(hwnd, L"License code:", 40, 130, 120, 24);

        AddEdit(hwnd, kControlLicenseCodeEdit, 165, 126, 320, 28);
        AddButton(hwnd, kControlActivateButton, L"Activate", 165, 175, 120, 32);
        AddButton(hwnd, kControlLogoutButton, L"Logout", 300, 175, 120, 32);
        AddButton(hwnd, kControlRefreshButton, L"Refresh", 435, 175, 120, 32);

        if (!g_last_error_text.empty()) {
            AddStaticText(hwnd, g_last_error_text.c_str(), 40, 235, 540, 28);
        }

        InvalidateRect(hwnd, nullptr, TRUE);
    }

    void BuildMainView(HWND hwnd) {
        ClearChildControls();

        std::wstring username_text = L"User: " + g_username;
        std::wstring license_text = L"License expires: ";

        if (!g_license_expiration_date.empty()) {
            license_text += g_license_expiration_date;
        }
        else {
            license_text += L"unknown";
        }

        AddStaticText(hwnd, username_text.c_str(), 40, 35, 520, 24);
        AddStaticText(hwnd, L"Antivirus functionality is unlocked.", 40, 75, 520, 24);
        AddStaticText(hwnd, license_text.c_str(), 40, 115, 520, 24);

        AddButton(hwnd, kControlRefreshButton, L"Refresh status", 40, 170, 140, 32);
        AddButton(hwnd, kControlLogoutButton, L"Logout", 200, 170, 120, 32);

        if (!g_last_error_text.empty()) {
            AddStaticText(hwnd, g_last_error_text.c_str(), 40, 235, 540, 28);
        }

        InvalidateRect(hwnd, nullptr, TRUE);
    }

    void BuildCurrentView(HWND hwnd) {
        if (!hwnd) {
            return;
        }

        if (g_ui_state == UiState::Login) {
            BuildLoginView(hwnd);
            return;
        }

        if (g_ui_state == UiState::Activation) {
            BuildActivationView(hwnd);
            return;
        }

        BuildMainView(hwnd);
    }

    void RefreshApplicationState() {
        g_is_authenticated = false;
        g_has_license = false;
        g_username.clear();
        g_license_expiration_date.clear();

        if (!RpcGetCurrentUserSafe()) {
            g_ui_state = UiState::Login;
            BuildCurrentView(g_main_window);
            return;
        }

        if (!g_is_authenticated) {
            g_ui_state = UiState::Login;
            BuildCurrentView(g_main_window);
            return;
        }

        if (!RpcGetLicenseInfoSafe()) {
            g_has_license = false;
        }

        if (!g_has_license) {
            g_ui_state = UiState::Activation;
            BuildCurrentView(g_main_window);
            return;
        }

        g_ui_state = UiState::Main;
        BuildCurrentView(g_main_window);
    }

    void PollLicenseStateWithoutResettingInput() {
        if (g_ui_state != UiState::Main) {
            return;
        }

        std::wstring old_username = g_username;
        std::wstring old_expiration = g_license_expiration_date;
        bool old_has_license = g_has_license;

        g_last_error_text.clear();

        RefreshApplicationState();

        if (old_has_license != g_has_license ||
            old_username != g_username ||
            old_expiration != g_license_expiration_date) {
            BuildCurrentView(g_main_window);
        }
    }

    void HandleLogin(HWND hwnd) {
        HWND username_edit = GetDlgItem(hwnd, kControlUsernameEdit);
        HWND password_edit = GetDlgItem(hwnd, kControlPasswordEdit);

        std::wstring username = GetWindowTextString(username_edit);
        std::wstring password = GetWindowTextString(password_edit);

        if (username.empty() || password.empty()) {
            g_last_error_text = L"Username and password are required.";
            BuildCurrentView(hwnd);
            return;
        }

        if (!RpcLoginSafe(username, password)) {
            g_ui_state = UiState::Login;
            BuildCurrentView(hwnd);
            return;
        }

        RefreshApplicationState();
    }

    void HandleActivate(HWND hwnd) {
        HWND license_edit = GetDlgItem(hwnd, kControlLicenseCodeEdit);
        std::wstring license_code = GetWindowTextString(license_edit);

        if (license_code.empty()) {
            g_last_error_text = L"License code is required.";
            BuildCurrentView(hwnd);
            return;
        }

        if (RpcCheckLicenseSafe(license_code)) {
            RefreshApplicationState();
            return;
        }

        std::wstring check_error = g_last_error_text;

        if (!RpcActivateLicenseSafe(license_code)) {
            std::wstring activate_error = g_last_error_text;
            g_last_error_text =
                L"License check failed first. " +
                check_error +
                L" Activation also failed. " +
                activate_error;

            g_ui_state = UiState::Activation;
            BuildCurrentView(hwnd);
            return;
        }

        RefreshApplicationState();
    }

    void HandleLogout(HWND hwnd) {
        RpcLogoutSafe();

        g_is_authenticated = false;
        g_has_license = false;
        g_username.clear();
        g_license_expiration_date.clear();

        g_ui_state = UiState::Login;
        BuildCurrentView(hwnd);
    }

    void RequestServiceStop() {
        if (!ConnectRpc()) {
            g_last_error_text = L"Cannot connect to service RPC.";
            BuildCurrentView(g_main_window);
            return;
        }

        RpcStopService();

        DisconnectRpc();
    }

    void ShowMainWindow() {
        if (!g_main_window) {
            return;
        }

        ShowWindow(g_main_window, SW_SHOWNORMAL);
        SetForegroundWindow(g_main_window);
    }

    void RemoveTrayIcon() {
        if (g_tray_icon.cbSize != 0) {
            Shell_NotifyIconW(NIM_DELETE, &g_tray_icon);
            g_tray_icon = {};
        }
    }

    void AddTrayIcon(HWND hwnd) {
        g_tray_icon = {};
        g_tray_icon.cbSize = sizeof(g_tray_icon);
        g_tray_icon.hWnd = hwnd;
        g_tray_icon.uID = kTrayIconId;
        g_tray_icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_tray_icon.uCallbackMessage = kTrayCallbackMessage;
        g_tray_icon.hIcon = LoadIconW(g_instance, MAKEINTRESOURCEW(IDI_TRAY_ICON));

        wcscpy_s(g_tray_icon.szTip, L"Tourism Service Tray App");

        Shell_NotifyIconW(NIM_ADD, &g_tray_icon);

        g_tray_icon.uVersion = NOTIFYICON_VERSION_4;

        Shell_NotifyIconW(NIM_SETVERSION, &g_tray_icon);
    }

    void ExitApplication() {
        g_is_exiting = true;
        KillTimer(g_main_window, kLicensePollTimerId);
        ClearChildControls();
        RemoveTrayIcon();
        PostQuitMessage(0);
    }

    void StopServiceAndExit() {
        RequestServiceStop();

        /*
            Do not close the GUI immediately.

            If the user confirms service stop on the private desktop,
            the service will terminate all launched TrayWin32App.exe processes.

            If the user clicks No or the confirmation cannot be shown,
            the tray app remains running.
        */
    }

    void ShowTrayMenu(HWND hwnd) {
        POINT cursor_position{};
        GetCursorPos(&cursor_position);

        HMENU menu = CreatePopupMenu();

        if (!menu) {
            return;
        }

        AppendMenuW(menu, MF_STRING, kMenuOpen, L"\u041E\u0442\u043A\u0440\u044B\u0442\u044C");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuExit, L"\u0412\u044B\u0445\u043E\u0434");

        SetForegroundWindow(hwnd);

        const UINT command = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
            cursor_position.x,
            cursor_position.y,
            0,
            hwnd,
            nullptr
        );

        DestroyMenu(menu);

        switch (command) {
        case kMenuOpen:
            ShowMainWindow();
            break;

        case kMenuExit:
            StopServiceAndExit();
            break;

        default:
            break;
        }
    }

    HMENU CreateMainMenu() {
        HMENU menu_bar = CreateMenu();
        HMENU file_menu = CreatePopupMenu();

        AppendMenuW(file_menu, MF_STRING, kMenuExit, L"\u0412\u044B\u0445\u043E\u0434");
        AppendMenuW(menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), L"\u0424\u0430\u0439\u043B");

        return menu_bar;
    }

    void PaintMainWindow(HWND hwnd) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rect{};
        GetClientRect(hwnd, &rect);

        HBRUSH background = CreateSolidBrush(RGB(45, 45, 45));
        FillRect(hdc, &rect, background);
        DeleteObject(background);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(230, 230, 230));

        RECT title_rect = rect;
        title_rect.top = 300;
        title_rect.bottom = 360;

        DrawTextW(
            hdc,
            L"Tourism Service Tray App",
            -1,
            &title_rect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE
        );

        EndPaint(hwnd, &ps);
    }

    LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param) {
        if (message == g_taskbar_created_message) {
            AddTrayIcon(hwnd);
            return 0;
        }

        switch (message) {
        case WM_CREATE:
            AddTrayIcon(hwnd);
            g_main_window = hwnd;
            SetTimer(hwnd, kLicensePollTimerId, kLicensePollIntervalMs, nullptr);
            RefreshApplicationState();
            return 0;

        case WM_TIMER:
            if (w_param == kLicensePollTimerId) {
                PollLicenseStateWithoutResettingInput();
                return 0;
            }

            break;

        case kTrayCallbackMessage:
            switch (LOWORD(l_param)) {
            case WM_LBUTTONUP:
            case NIN_SELECT:
            case NIN_KEYSELECT:
                ShowMainWindow();
                return 0;

            case WM_RBUTTONUP:
            case WM_CONTEXTMENU:
                ShowTrayMenu(hwnd);
                return 0;

            default:
                return 0;
            }

        case WM_COMMAND:
            switch (LOWORD(w_param)) {
            case kControlLoginButton:
                HandleLogin(hwnd);
                return 0;

            case kControlActivateButton:
                HandleActivate(hwnd);
                return 0;

            case kControlLogoutButton:
                HandleLogout(hwnd);
                return 0;

            case kControlRefreshButton:
                g_last_error_text.clear();
                RefreshApplicationState();
                return 0;

            case kMenuExit:
                StopServiceAndExit();
                return 0;

            default:
                break;
            }

            break;

        case WM_PAINT:
            PaintMainWindow(hwnd);
            return 0;

        case WM_CLOSE:
            if (!g_is_exiting) {
                ShowWindow(hwnd, SW_HIDE);
                return 0;
            }

            break;

        case WM_DESTROY:
            KillTimer(hwnd, kLicensePollTimerId);
            ClearChildControls();
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;

        default:
            break;
        }

        return DefWindowProcW(hwnd, message, w_param, l_param);
    }

    bool RegisterMainWindowClass() {
        WNDCLASSEXW window_class{};
        window_class.cbSize = sizeof(window_class);
        window_class.lpfnWndProc = WindowProc;
        window_class.hInstance = g_instance;
        window_class.hIcon = LoadIconW(g_instance, MAKEINTRESOURCEW(IDI_TRAY_ICON));
        window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        window_class.lpszClassName = kWindowClassName;
        window_class.hIconSm = LoadIconW(g_instance, MAKEINTRESOURCEW(IDI_TRAY_ICON));

        return RegisterClassExW(&window_class) != 0;
    }

    HWND CreateMainWindow() {
        return CreateWindowExW(
            0,
            kWindowClassName,
            kWindowTitle,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            640,
            420,
            nullptr,
            CreateMainMenu(),
            g_instance,
            nullptr
        );
    }

}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    HeapFree(GetProcessHeap(), 0, pointer);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    g_instance = instance;

    if (HasArgument(L"--secure-stop-confirm")) {
        return RunSecureStopConfirmation();
    }

    if (IsServiceStopped()) {
        StartServiceAndWaitRunning();
        return 0;
    }

    if (!IsParentServiceProcess()) {
        return 0;
    }

    g_single_instance_mutex = CreateMutexW(nullptr, TRUE, kMutexName);

    if (!g_single_instance_mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (g_single_instance_mutex) {
            CloseHandle(g_single_instance_mutex);
        }

        return 0;
    }

    g_taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");

    if (!RegisterMainWindowClass()) {
        CloseHandle(g_single_instance_mutex);
        return 1;
    }

    g_main_window = CreateMainWindow();

    if (!g_main_window) {
        CloseHandle(g_single_instance_mutex);
        return 1;
    }

    if (!HasHiddenStartupArgument()) {
        ShowWindow(g_main_window, show_command);
        UpdateWindow(g_main_window);
    }

    MSG message{};

    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (g_single_instance_mutex) {
        ReleaseMutex(g_single_instance_mutex);
        CloseHandle(g_single_instance_mutex);
    }

    return static_cast<int>(message.wParam);
}