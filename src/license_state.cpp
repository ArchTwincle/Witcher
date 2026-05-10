#include "license_state.h"

#include <windows.h>

#include <ctime>

namespace witcher {

    namespace {
        CRITICAL_SECTION g_license_lock;
        LicenseState g_license_state;
    }

    void InitLicenseState() {
        InitializeCriticalSection(&g_license_lock);
    }

    void FreeLicenseState() {
        DeleteCriticalSection(&g_license_lock);
    }

    void SetLicenseTicket(
        const std::string& licenseTicket,
        long long ticketLifetimeSeconds,
        const std::string& expirationDate,
        const std::string& licenseCode,
        const std::string& macAddress,
        const std::string& productId
    ) {
        EnterCriticalSection(&g_license_lock);

        g_license_state.hasLicenseTicket = true;
        g_license_state.licenseTicket = licenseTicket;
        g_license_state.ticketLifetimeSeconds = ticketLifetimeSeconds;
        g_license_state.ticketSavedAtUnix = static_cast<long long>(std::time(nullptr));
        g_license_state.expirationDate = expirationDate;

        if (!licenseCode.empty()) {
            g_license_state.licenseCode = licenseCode;
        }

        if (!macAddress.empty()) {
            g_license_state.macAddress = macAddress;
        }

        if (!productId.empty()) {
            g_license_state.productId = productId;
        }

        LeaveCriticalSection(&g_license_lock);
    }

    void ClearLicenseTicket() {
        EnterCriticalSection(&g_license_lock);

        g_license_state = LicenseState{};

        LeaveCriticalSection(&g_license_lock);
    }

    bool HasLicenseTicket() {
        EnterCriticalSection(&g_license_lock);

        bool result = g_license_state.hasLicenseTicket;

        LeaveCriticalSection(&g_license_lock);
        return result;
    }

    std::string GetLicenseTicket() {
        EnterCriticalSection(&g_license_lock);

        std::string result = g_license_state.licenseTicket;

        LeaveCriticalSection(&g_license_lock);
        return result;
    }

    bool GetLicenseRefreshInfo(
        long long* ticketSavedAtUnix,
        long long* ticketLifetimeSeconds
    ) {
        EnterCriticalSection(&g_license_lock);

        if (ticketSavedAtUnix) {
            *ticketSavedAtUnix = g_license_state.ticketSavedAtUnix;
        }

        if (ticketLifetimeSeconds) {
            *ticketLifetimeSeconds = g_license_state.ticketLifetimeSeconds;
        }

        bool result = g_license_state.hasLicenseTicket;

        LeaveCriticalSection(&g_license_lock);
        return result;
    }

    bool GetLicenseRefreshRequestInfo(
        long long* ticketSavedAtUnix,
        long long* ticketLifetimeSeconds,
        std::string* licenseCode,
        std::string* macAddress,
        std::string* productId
    ) {
        EnterCriticalSection(&g_license_lock);

        bool result =
            g_license_state.hasLicenseTicket &&
            !g_license_state.licenseCode.empty() &&
            !g_license_state.macAddress.empty() &&
            !g_license_state.productId.empty();

        if (ticketSavedAtUnix) {
            *ticketSavedAtUnix = g_license_state.ticketSavedAtUnix;
        }

        if (ticketLifetimeSeconds) {
            *ticketLifetimeSeconds = g_license_state.ticketLifetimeSeconds;
        }

        if (licenseCode) {
            *licenseCode = g_license_state.licenseCode;
        }

        if (macAddress) {
            *macAddress = g_license_state.macAddress;
        }

        if (productId) {
            *productId = g_license_state.productId;
        }

        LeaveCriticalSection(&g_license_lock);
        return result;
    }

    bool GetLicensePublicInfo(
        std::string* expirationDate
    ) {
        EnterCriticalSection(&g_license_lock);

        bool result = g_license_state.hasLicenseTicket;

        if (expirationDate) {
            *expirationDate = g_license_state.expirationDate;
        }

        LeaveCriticalSection(&g_license_lock);
        return result;
    }

}