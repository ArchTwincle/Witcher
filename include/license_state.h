#pragma once

#include <string>

namespace witcher {

    struct LicenseState {
        bool hasLicenseTicket = false;

        std::string licenseTicket;

        long long ticketLifetimeSeconds = 0;
        long long ticketSavedAtUnix = 0;

        std::string expirationDate;
    };

    void InitLicenseState();
    void FreeLicenseState();

    void SetLicenseTicket(
        const std::string& licenseTicket,
        long long ticketLifetimeSeconds = 0,
        const std::string& expirationDate = ""
    );

    void ClearLicenseTicket();

    bool HasLicenseTicket();

    std::string GetLicenseTicket();

    bool GetLicenseRefreshInfo(
        long long* ticketSavedAtUnix,
        long long* ticketLifetimeSeconds
    );

    bool GetLicensePublicInfo(
        std::string* expirationDate
    );

}