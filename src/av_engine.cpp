#include "av_engine.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <filesystem>

#pragma comment(lib, "advapi32.lib")

namespace witcher_av {

    namespace {

        constexpr unsigned long kSha256Length = 32;
        constexpr unsigned long long kDefaultOffsetEnd = 1024ull * 1024ull * 1024ull;

        using AvTree = std::map<unsigned long long, std::vector<AvRecord>>;

        std::mutex g_database_lock;
        AvTree g_database;
        bool g_database_loaded = false;
        std::wstring g_release_date = L"2026-05-14";

        std::vector<unsigned char> ToBytes(const char* text) {
            std::vector<unsigned char> bytes;

            if (!text) {
                return bytes;
            }

            while (*text) {
                bytes.push_back(static_cast<unsigned char>(*text));
                ++text;
            }

            return bytes;
        }

        unsigned long long ReadPrefixFromBytes(
            const std::vector<unsigned char>& bytes,
            size_t offset
        ) {
            if (offset + 8 > bytes.size()) {
                return 0;
            }

            unsigned long long value = 0;

            for (size_t i = 0; i < 8; ++i) {
                value |= static_cast<unsigned long long>(bytes[offset + i]) << (i * 8);
            }

            return value;
        }

        bool ComputeSha256(
            const std::vector<unsigned char>& data,
            std::vector<unsigned char>* hash
        ) {
            if (!hash) {
                return false;
            }

            hash->clear();

            HCRYPTPROV provider = 0;
            HCRYPTHASH hash_handle = 0;

            if (!CryptAcquireContextW(
                &provider,
                nullptr,
                nullptr,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT
            )) {
                return false;
            }

            if (!CryptCreateHash(
                provider,
                CALG_SHA_256,
                0,
                0,
                &hash_handle
            )) {
                CryptReleaseContext(provider, 0);
                return false;
            }

            BOOL hashed = CryptHashData(
                hash_handle,
                data.data(),
                static_cast<DWORD>(data.size()),
                0
            );

            if (!hashed) {
                CryptDestroyHash(hash_handle);
                CryptReleaseContext(provider, 0);
                return false;
            }

            DWORD hash_length = kSha256Length;
            std::vector<unsigned char> local_hash(hash_length);

            BOOL got_hash = CryptGetHashParam(
                hash_handle,
                HP_HASHVAL,
                local_hash.data(),
                &hash_length,
                0
            );

            CryptDestroyHash(hash_handle);
            CryptReleaseContext(provider, 0);

            if (!got_hash) {
                return false;
            }

            local_hash.resize(hash_length);
            *hash = std::move(local_hash);
            return true;
        }

        bool ComputeRecordSignature(
            const AvRecord& record,
            std::vector<unsigned char>* signature
        ) {
            if (!signature) {
                return false;
            }

            std::vector<unsigned char> data;

            auto append_u64 = [&data](unsigned long long value) {
                for (int i = 0; i < 8; ++i) {
                    data.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xFF));
                }
                };

            auto append_u32 = [&data](unsigned long value) {
                for (int i = 0; i < 4; ++i) {
                    data.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xFF));
                }
                };

            append_u64(record.objectSignaturePrefix);
            append_u32(record.objectSignatureLength);

            data.insert(
                data.end(),
                record.objectSignature.begin(),
                record.objectSignature.end()
            );

            append_u64(record.offsetBegin);
            append_u64(record.offsetEnd);
            append_u64(static_cast<unsigned long long>(record.objectType));

            return ComputeSha256(data, signature);
        }

        AvRecord MakeRecord(
            const char* signature_text,
            unsigned long long offset_begin,
            unsigned long long offset_end,
            AvObjectType object_type,
            const wchar_t* threat_name
        ) {
            AvRecord record{};

            std::vector<unsigned char> signature_bytes = ToBytes(signature_text);

            record.objectSignaturePrefix = ReadPrefixFromBytes(signature_bytes, 0);
            record.objectSignatureLength = static_cast<unsigned long>(signature_bytes.size());
            record.offsetBegin = offset_begin;
            record.offsetEnd = offset_end;
            record.objectType = object_type;
            record.threatName = threat_name ? threat_name : L"Unknown threat";

            ComputeSha256(signature_bytes, &record.objectSignature);
            ComputeRecordSignature(record, &record.avRecordSignature);

            return record;
        }

        void AddRecordUnlocked(const AvRecord& record) {
            g_database[record.objectSignaturePrefix].push_back(record);
        }

        bool ReadFileBytes(
            const std::wstring& path,
            std::vector<unsigned char>* bytes
        ) {
            if (!bytes) {
                return false;
            }

            bytes->clear();

            std::ifstream file(path, std::ios::binary);

            if (!file) {
                return false;
            }

            file.seekg(0, std::ios::end);
            std::streamoff size = file.tellg();

            if (size < 0) {
                return false;
            }

            file.seekg(0, std::ios::beg);

            bytes->resize(static_cast<size_t>(size));

            if (!bytes->empty()) {
                file.read(
                    reinterpret_cast<char*>(bytes->data()),
                    static_cast<std::streamsize>(bytes->size())
                );
            }

            return file.good() || file.eof();
        }

        std::wstring ToLower(std::wstring value) {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(towlower(ch));
                });

            return value;
        }

        bool EndsWith(
            const std::wstring& value,
            const std::wstring& suffix
        ) {
            if (suffix.size() > value.size()) {
                return false;
            }

            return std::equal(
                suffix.rbegin(),
                suffix.rend(),
                value.rbegin()
            );
        }

        AvObjectType DetectObjectType(
            const std::wstring& path,
            const std::vector<unsigned char>& bytes
        ) {
            std::wstring lower_path = ToLower(path);

            if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
                return AvObjectType::PeFile;
            }

            if (EndsWith(lower_path, L".exe") || EndsWith(lower_path, L".dll")) {
                return AvObjectType::PeFile;
            }

            if (EndsWith(lower_path, L".ps1")) {
                return AvObjectType::PowerShellScript;
            }

            if (EndsWith(lower_path, L".js")) {
                return AvObjectType::JavaScript;
            }

            if (EndsWith(lower_path, L".py")) {
                return AvObjectType::PythonScript;
            }

            return AvObjectType::Unknown;
        }

        void CopyWideString(
            const std::wstring& value,
            wchar_t* destination,
            size_t capacity
        ) {
            if (!destination || capacity == 0) {
                return;
            }

            destination[0] = L'\0';

            if (value.empty()) {
                return;
            }

            wcsncpy_s(
                destination,
                capacity,
                value.c_str(),
                _TRUNCATE
            );
        }

        bool ScanBytesUnlocked(
            const std::wstring& path,
            const std::vector<unsigned char>& bytes,
            ScanResult* result
        ) {
            if (!result) {
                return false;
            }

            result->scanned = true;
            result->malicious = false;
            result->offset = 0;
            result->threatName[0] = L'\0';
            result->objectPath[0] = L'\0';

            CopyWideString(path, result->objectPath, _countof(result->objectPath));

            if (!g_database_loaded || bytes.size() < 8) {
                return true;
            }

            AvObjectType object_type = DetectObjectType(path, bytes);

            size_t position = 0;

            while (position + 8 <= bytes.size()) {
                unsigned long long prefix = ReadPrefixFromBytes(bytes, position);

                auto found = g_database.find(prefix);

                if (found == g_database.end()) {
                    ++position;
                    continue;
                }

                const std::vector<AvRecord>& records = found->second;

                for (const AvRecord& record : records) {
                    if (record.objectType != object_type) {
                        continue;
                    }

                    if (position < record.offsetBegin || position > record.offsetEnd) {
                        continue;
                    }

                    if (record.objectSignatureLength < 8) {
                        continue;
                    }

                    size_t full_length = static_cast<size_t>(record.objectSignatureLength);

                    if (position + full_length > bytes.size()) {
                        continue;
                    }

                    std::vector<unsigned char> candidate(
                        bytes.begin() + static_cast<std::ptrdiff_t>(position),
                        bytes.begin() + static_cast<std::ptrdiff_t>(position + full_length)
                    );

                    std::vector<unsigned char> candidate_hash;

                    if (!ComputeSha256(candidate, &candidate_hash)) {
                        continue;
                    }

                    if (candidate_hash == record.objectSignature) {
                        result->malicious = true;
                        result->maliciousFiles = 1;
                        result->offset = static_cast<unsigned long long>(position);
                        CopyWideString(record.threatName, result->threatName, _countof(result->threatName));
                        return true;
                    }
                }

                ++position;
            }

            return true;
        }

        bool IsRegularFile(const std::filesystem::directory_entry& entry) {
            std::error_code error;
            return entry.is_regular_file(error);
        }

    }

    void InitializeAvEngine() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_database_loaded = false;
        g_release_date = L"2026-05-14";
    }

    void FreeAvEngine() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_database_loaded = false;
    }

    bool LoadDefaultDatabase() {
        std::lock_guard<std::mutex> guard(g_database_lock);

        g_database.clear();

        /*
            Demo in-memory AV database.

            Test files:
            - test.ps1 containing: WITCHER_SCRIPT_TEST_MALWARE
            - test.js containing: WITCHER_JS_TEST_MALWARE
            - test.exe-like file starting with MZ and containing: WITCHER_PE_TEST_MALWARE
        */

        AddRecordUnlocked(MakeRecord(
            "WITCHER_SCRIPT_TEST_MALWARE",
            0,
            kDefaultOffsetEnd,
            AvObjectType::PowerShellScript,
            L"Witcher.Test.PowerShell"
        ));

        AddRecordUnlocked(MakeRecord(
            "WITCHER_JS_TEST_MALWARE",
            0,
            kDefaultOffsetEnd,
            AvObjectType::JavaScript,
            L"Witcher.Test.JavaScript"
        ));

        AddRecordUnlocked(MakeRecord(
            "WITCHER_PE_TEST_MALWARE",
            0,
            kDefaultOffsetEnd,
            AvObjectType::PeFile,
            L"Witcher.Test.PE"
        ));

        g_database_loaded = true;
        g_release_date = L"2026-05-14";

        return true;
    }

    void ClearDatabase() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_database_loaded = false;
    }

    bool IsDatabaseLoaded() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        return g_database_loaded;
    }

    AvDatabaseInfo GetDatabaseInfo() {
        std::lock_guard<std::mutex> guard(g_database_lock);

        AvDatabaseInfo info{};
        info.loaded = g_database_loaded;

        wcsncpy_s(
            info.releaseDate,
            _countof(info.releaseDate),
            g_release_date.c_str(),
            _TRUNCATE
        );

        unsigned long long count = 0;

        for (const auto& pair : g_database) {
            count += static_cast<unsigned long long>(pair.second.size());
        }

        info.recordCount = count;

        return info;
    }

    bool ScanFile(
        const std::wstring& path,
        ScanResult* result
    ) {
        if (!result) {
            return false;
        }

        *result = ScanResult{};
        result->scannedFiles = 1;

        std::vector<unsigned char> bytes;

        if (!ReadFileBytes(path, &bytes)) {
            result->scanned = false;
            CopyWideString(path, result->objectPath, _countof(result->objectPath));
            return false;
        }

        std::lock_guard<std::mutex> guard(g_database_lock);
        return ScanBytesUnlocked(path, bytes, result);
    }

    bool ScanDirectory(
        const std::wstring& path,
        ScanResult* result
    ) {
        if (!result) {
            return false;
        }

        *result = ScanResult{};

        std::error_code error;

        if (!std::filesystem::exists(path, error) ||
            !std::filesystem::is_directory(path, error)) {
            return false;
        }

        for (const auto& entry : std::filesystem::recursive_directory_iterator(path, error)) {
            if (error) {
                break;
            }

            if (!IsRegularFile(entry)) {
                continue;
            }

            ScanResult local_result{};

            ++result->scannedFiles;

            if (ScanFile(entry.path().wstring(), &local_result) &&
                local_result.malicious) {
                result->scanned = true;
                result->malicious = true;
                result->maliciousFiles += 1;
                result->offset = local_result.offset;
                CopyWideString(local_result.threatName, result->threatName, _countof(result->threatName));
                CopyWideString(local_result.objectPath, result->objectPath, _countof(result->objectPath));
                return true;
            }
        }

        result->scanned = true;
        result->malicious = false;
        return true;
    }

}