#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace witcher_av {

    enum class AvObjectType : unsigned long long {
        Unknown = 0,
        PeFile = 1,
        PowerShellScript = 2,
        JavaScript = 3,
        PythonScript = 4
    };

    struct AvRecord {
        unsigned long long objectSignaturePrefix = 0;
        unsigned long objectSignatureLength = 0;
        std::vector<unsigned char> objectSignature;
        std::vector<unsigned char> rawSignature;
        unsigned long long offsetBegin = 0;
        unsigned long long offsetEnd = 0;
        AvObjectType objectType = AvObjectType::Unknown;
        std::vector<unsigned char> avRecordSignature;
        std::wstring threatName;
    };

    struct AvDatabaseInfo {
        bool loaded = false;
        wchar_t releaseDate[64]{};
        unsigned long long recordCount = 0;
    };

    struct ScanResult {
        bool scanned = false;
        bool malicious = false;
        unsigned long long scannedFiles = 0;
        unsigned long long maliciousFiles = 0;
        wchar_t threatName[256]{};
        wchar_t objectPath[1024]{};
        unsigned long long offset = 0;
    };

    void InitializeAvEngine();
    void FreeAvEngine();

    bool LoadDefaultDatabase();
    void ClearDatabase();

    bool IsDatabaseLoaded();
    AvDatabaseInfo GetDatabaseInfo();

    bool ScanFile(
        const std::wstring& path,
        ScanResult* result
    );

    bool ScanDirectory(
        const std::wstring& path,
        ScanResult* result
    );

    bool ScanFixedDrives(
        ScanResult* result
    );

}