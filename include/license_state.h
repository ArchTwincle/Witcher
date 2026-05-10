#pragma once

#include <string>

namespace witcher {

    struct LicenseState {
        bool hasLicenseTicket = false;

        std::string licenseTicket;

        long long ticketLifetimeSeconds = 0;
        long long ticketSavedAtUnix = 0;

        std::string expirationDate;

        std::string licenseCode;
        std::string macAddress;
        std::string productId;
    };

    void InitLicenseState();
    void FreeLicenseState();

    void SetLicenseTicket(
        const std::string& licenseTicket,
        long long ticketLifetimeSeconds = 0,
        const std::string& expirationDate = "",
        const std::string& licenseCode = "",
        const std::string& macAddress = "",
        const std::string& productId = ""
    );

    void ClearLicenseTicket();

    bool HasLicenseTicket();

    std::string GetLicenseTicket();

    bool GetLicenseRefreshInfo(
        long long* ticketSavedAtUnix,
        long long* ticketLifetimeSeconds
    );

    bool GetLicenseRefreshRequestInfo(
        long long* ticketSavedAtUnix,
        long long* ticketLifetimeSeconds,
        std::string* licenseCode,
        std::string* macAddress,
        std::string* productId
    );

    bool GetLicensePublicInfo(
        std::string* expirationDate
    );

}