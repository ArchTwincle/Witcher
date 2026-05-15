#include "av_engine.h"

#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

namespace witcher_av {

    namespace {

        constexpr unsigned long kSha256Length = 32;
        constexpr unsigned long long kDefaultOffsetEnd = 1024ull * 1024ull * 1024ull;

        using AvTree = std::map<unsigned long long, std::vector<AvRecord>>;

        struct AhoNode {
            std::map<unsigned char, int> next;
            int fail = 0;
            std::vector<size_t> outputRecordIndexes;
        };

        std::mutex g_database_lock;
        AvTree g_database;
        std::vector<AvRecord> g_flat_records;
        std::vector<AhoNode> g_aho_nodes;
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

            BOOL hashed = TRUE;

            if (!data.empty()) {
                hashed = CryptHashData(
                    hash_handle,
                    data.data(),
                    static_cast<DWORD>(data.size()),
                    0
                );
            }

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

            record.rawSignature = signature_bytes;
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
            g_flat_records.push_back(record);
        }

        void BuildAhoCorasickUnlocked() {
            g_aho_nodes.clear();
            g_aho_nodes.push_back(AhoNode{});

            for (size_t record_index = 0; record_index < g_flat_records.size(); ++record_index) {
                const AvRecord& record = g_flat_records[record_index];

                if (record.rawSignature.empty()) {
                    continue;
                }

                int node = 0;

                for (unsigned char ch : record.rawSignature) {
                    auto found = g_aho_nodes[node].next.find(ch);

                    if (found == g_aho_nodes[node].next.end()) {
                        int new_node = static_cast<int>(g_aho_nodes.size());
                        g_aho_nodes[node].next[ch] = new_node;
                        g_aho_nodes.push_back(AhoNode{});
                        node = new_node;
                    }
                    else {
                        node = found->second;
                    }
                }

                g_aho_nodes[node].outputRecordIndexes.push_back(record_index);
            }

            std::queue<int> queue;

            for (const auto& edge : g_aho_nodes[0].next) {
                int child = edge.second;
                g_aho_nodes[child].fail = 0;
                queue.push(child);
            }

            while (!queue.empty()) {
                int current = queue.front();
                queue.pop();

                for (const auto& edge : g_aho_nodes[current].next) {
                    unsigned char ch = edge.first;
                    int child = edge.second;

                    int fallback = g_aho_nodes[current].fail;

                    while (fallback != 0 &&
                        g_aho_nodes[fallback].next.find(ch) == g_aho_nodes[fallback].next.end()) {
                        fallback = g_aho_nodes[fallback].fail;
                    }

                    auto found = g_aho_nodes[fallback].next.find(ch);

                    if (found != g_aho_nodes[fallback].next.end()) {
                        g_aho_nodes[child].fail = found->second;
                    }
                    else {
                        g_aho_nodes[child].fail = 0;
                    }

                    const auto& fail_outputs = g_aho_nodes[g_aho_nodes[child].fail].outputRecordIndexes;
                    g_aho_nodes[child].outputRecordIndexes.insert(
                        g_aho_nodes[child].outputRecordIndexes.end(),
                        fail_outputs.begin(),
                        fail_outputs.end()
                    );

                    queue.push(child);
                }
            }
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

        bool VerifyRecordWithHash(
            const AvRecord& record,
            const std::vector<unsigned char>& bytes,
            size_t position
        ) {
            if (record.objectSignatureLength < 8) {
                return false;
            }

            size_t full_length = static_cast<size_t>(record.objectSignatureLength);

            if (position + full_length > bytes.size()) {
                return false;
            }

            std::vector<unsigned char> candidate(
                bytes.begin() + static_cast<std::ptrdiff_t>(position),
                bytes.begin() + static_cast<std::ptrdiff_t>(position + full_length)
            );

            std::vector<unsigned char> candidate_hash;

            if (!ComputeSha256(candidate, &candidate_hash)) {
                return false;
            }

            return candidate_hash == record.objectSignature;
        }

        bool ScanBytesWithMapUnlocked(
            const std::wstring& path,
            const std::vector<unsigned char>& bytes,
            ScanResult* result
        ) {
            if (!result) {
                return false;
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

                    if (!VerifyRecordWithHash(record, bytes, position)) {
                        continue;
                    }

                    result->malicious = true;
                    result->maliciousFiles = 1;
                    result->offset = static_cast<unsigned long long>(position);
                    CopyWideString(record.threatName, result->threatName, _countof(result->threatName));
                    return true;
                }

                ++position;
            }

            return true;
        }

        bool ScanBytesWithAhoCorasickUnlocked(
            const std::wstring& path,
            const std::vector<unsigned char>& bytes,
            ScanResult* result
        ) {
            if (!result) {
                return false;
            }

            if (g_aho_nodes.empty()) {
                return ScanBytesWithMapUnlocked(path, bytes, result);
            }

            AvObjectType object_type = DetectObjectType(path, bytes);
            int node = 0;

            for (size_t i = 0; i < bytes.size(); ++i) {
                unsigned char ch = bytes[i];

                while (node != 0 &&
                    g_aho_nodes[node].next.find(ch) == g_aho_nodes[node].next.end()) {
                    node = g_aho_nodes[node].fail;
                }

                auto found = g_aho_nodes[node].next.find(ch);

                if (found != g_aho_nodes[node].next.end()) {
                    node = found->second;
                }
                else {
                    node = 0;
                }

                if (g_aho_nodes[node].outputRecordIndexes.empty()) {
                    continue;
                }

                for (size_t record_index : g_aho_nodes[node].outputRecordIndexes) {
                    if (record_index >= g_flat_records.size()) {
                        continue;
                    }

                    const AvRecord& record = g_flat_records[record_index];

                    if (record.rawSignature.size() > i + 1) {
                        continue;
                    }

                    size_t position = i + 1 - record.rawSignature.size();

                    if (record.objectType != object_type) {
                        continue;
                    }

                    if (position < record.offsetBegin || position > record.offsetEnd) {
                        continue;
                    }

                    if (!VerifyRecordWithHash(record, bytes, position)) {
                        continue;
                    }

                    result->malicious = true;
                    result->maliciousFiles = 1;
                    result->offset = static_cast<unsigned long long>(position);
                    CopyWideString(record.threatName, result->threatName, _countof(result->threatName));
                    return true;
                }
            }

            return true;
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

            return ScanBytesWithAhoCorasickUnlocked(path, bytes, result);
        }

        bool IsRegularFile(const std::filesystem::directory_entry& entry) {
            std::error_code error;
            return entry.is_regular_file(error);
        }

        void MergeDirectoryResult(
            ScanResult* total_result,
            const ScanResult& local_result
        ) {
            if (!total_result) {
                return;
            }

            if (local_result.malicious) {
                total_result->malicious = true;
                total_result->maliciousFiles += local_result.maliciousFiles;

                if (total_result->threatName[0] == L'\0') {
                    CopyWideString(local_result.threatName, total_result->threatName, _countof(total_result->threatName));
                    CopyWideString(local_result.objectPath, total_result->objectPath, _countof(total_result->objectPath));
                    total_result->offset = local_result.offset;
                }
            }
        }

        bool ScanDirectoryInternal(
            const std::wstring& path,
            ScanResult* result
        ) {
            if (!result) {
                return false;
            }

            std::error_code error;

            if (!std::filesystem::exists(path, error) ||
                !std::filesystem::is_directory(path, error)) {
                return false;
            }

            result->scanned = true;

            std::filesystem::recursive_directory_iterator iterator(
                path,
                std::filesystem::directory_options::skip_permission_denied,
                error
            );

            std::filesystem::recursive_directory_iterator end;

            while (!error && iterator != end) {
                const auto& entry = *iterator;

                if (IsRegularFile(entry)) {
                    ScanResult local_result{};
                    ++result->scannedFiles;

                    if (ScanFile(entry.path().wstring(), &local_result)) {
                        MergeDirectoryResult(result, local_result);
                    }
                }

                iterator.increment(error);
            }

            return true;
        }

    }

    void InitializeAvEngine() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_flat_records.clear();
        g_aho_nodes.clear();
        g_database_loaded = false;
        g_release_date = L"2026-05-14";
    }

    void FreeAvEngine() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_flat_records.clear();
        g_aho_nodes.clear();
        g_database_loaded = false;
    }

    bool LoadDefaultDatabase() {
        std::lock_guard<std::mutex> guard(g_database_lock);

        g_database.clear();
        g_flat_records.clear();
        g_aho_nodes.clear();

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

        AddRecordUnlocked(MakeRecord(
            "WITCHER_PY_TEST_MALWARE",
            0,
            kDefaultOffsetEnd,
            AvObjectType::PythonScript,
            L"Witcher.Test.Python"
        ));

        BuildAhoCorasickUnlocked();

        g_database_loaded = true;
        g_release_date = L"2026-05-14";

        return true;
    }

    void ClearDatabase() {
        std::lock_guard<std::mutex> guard(g_database_lock);
        g_database.clear();
        g_flat_records.clear();
        g_aho_nodes.clear();
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
        return ScanDirectoryInternal(path, result);
    }

    bool ScanFixedDrives(
        ScanResult* result
    ) {
        if (!result) {
            return false;
        }

        *result = ScanResult{};
        result->scanned = true;

        DWORD drives_mask = GetLogicalDrives();

        if (drives_mask == 0) {
            return false;
        }

        constexpr unsigned long long kMaxFilesForDemo = 3000;

        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            DWORD bit = 1u << (letter - L'A');

            if ((drives_mask & bit) == 0) {
                continue;
            }

            std::wstring root;
            root.push_back(letter);
            root += L":\\";

            UINT drive_type = GetDriveTypeW(root.c_str());

            if (drive_type != DRIVE_FIXED) {
                continue;
            }

            std::error_code error;

            std::filesystem::recursive_directory_iterator iterator(
                root,
                std::filesystem::directory_options::skip_permission_denied,
                error
            );

            std::filesystem::recursive_directory_iterator end;

            while (!error && iterator != end) {
                const std::wstring current_path = iterator->path().wstring();

                if (current_path.find(L"\\Windows\\") != std::wstring::npos ||
                    current_path.find(L"\\Program Files\\") != std::wstring::npos ||
                    current_path.find(L"\\Program Files (x86)\\") != std::wstring::npos ||
                    current_path.find(L"\\AppData\\") != std::wstring::npos ||
                    current_path.find(L"\\System Volume Information\\") != std::wstring::npos ||
                    current_path.find(L"\\$Recycle.Bin\\") != std::wstring::npos) {
                    iterator.disable_recursion_pending();
                    iterator.increment(error);
                    continue;
                }

                if (IsRegularFile(*iterator)) {
                    ScanResult local_result{};
                    ++result->scannedFiles;

                    if (ScanFile(iterator->path().wstring(), &local_result)) {
                        MergeDirectoryResult(result, local_result);
                    }

                    if (result->scannedFiles >= kMaxFilesForDemo) {
                        return true;
                    }
                }

                iterator.increment(error);
            }
        }

        return true;
    }

}
namespace witcher_av {

    bool LoadDatabaseOnServiceStart() {
        std::lock_guard<std::mutex> guard(g_database_lock);

        constexpr unsigned long kMagic = 0x31424457; // WDB1
        constexpr unsigned long kVersion = 1;
        constexpr size_t kSigSize = 32;
        constexpr char kSigKey[] = "WITCHER_AVDB_SIGN_KEY_V1";

        struct Manifest {
            unsigned long magic = 0;
            unsigned long version = 0;
            unsigned long recordCount = 0;
            unsigned long long releaseDateUnix = 0;
            unsigned char recordsDigest[32]{};
            unsigned char manifestSig[32]{};
        };

        struct RecordHdr {
            unsigned long rawSigLen = 0;
            unsigned long long offsetBegin = 0;
            unsigned long long offsetEnd = 0;
            unsigned long long objectType = 0;
            unsigned long threatNameLen = 0;
            unsigned char recordSig[32]{};
        };

        auto moduleDir = []() {
            wchar_t path[MAX_PATH]{};
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            return std::filesystem::path(path).parent_path();
        };

        const auto baseDir = moduleDir();
        const auto manifestPath = baseDir / L"av_manifest.bin";
        const auto recordsPath = baseDir / L"av_records.bin";
        const auto backupManifestPath = baseDir / L"av_manifest.bak";
        const auto backupRecordsPath = baseDir / L"av_records.bak";

        auto downloadBinary = [&](const wchar_t* endpoint, std::string* out) -> bool {
            if (!out) {
                return false;
            }

            out->clear();

            HINTERNET session = WinHttpOpen(
                L"WitcherTrayService/1.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );
            if (!session) {
                return false;
            }

            HINTERNET connect = WinHttpConnect(session, L"localhost", 8443, 0);
            if (!connect) {
                WinHttpCloseHandle(session);
                return false;
            }

            HINTERNET request = WinHttpOpenRequest(
                connect,
                L"GET",
                endpoint,
                nullptr,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE
            );
            if (!request) {
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return false;
            }

            DWORD securityFlags =
                SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

            if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
                !WinHttpReceiveResponse(request, nullptr)) {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return false;
            }

            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            if (!WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &statusCodeSize,
                WINHTTP_NO_HEADER_INDEX
            ) || statusCode != 200) {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return false;
            }

            while (true) {
                DWORD availableSize = 0;
                if (!WinHttpQueryDataAvailable(request, &availableSize)) {
                    break;
                }
                if (availableSize == 0) {
                    break;
                }

                std::string chunk(availableSize, '\0');
                DWORD downloaded = 0;
                if (!WinHttpReadData(request, chunk.data(), availableSize, &downloaded)) {
                    break;
                }
                chunk.resize(downloaded);
                *out += chunk;
            }

            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return !out->empty();
        };
        auto sign = [&](const std::vector<unsigned char>& payload) {
            std::vector<unsigned char> signedPayload;
            signedPayload.insert(signedPayload.end(), kSigKey, kSigKey + sizeof(kSigKey) - 1);
            signedPayload.insert(signedPayload.end(), payload.begin(), payload.end());
            std::vector<unsigned char> digest;
            ComputeSha256(signedPayload, &digest);
            return digest;
        };

        auto writeCurrentToFiles = [&]() {
            std::vector<unsigned char> recordsBlob;

            for (const auto& record : g_flat_records) {
                RecordHdr hdr{};
                hdr.rawSigLen = static_cast<unsigned long>(record.rawSignature.size());
                hdr.offsetBegin = record.offsetBegin;
                hdr.offsetEnd = record.offsetEnd;
                hdr.objectType = static_cast<unsigned long long>(record.objectType);
                hdr.threatNameLen = static_cast<unsigned long>(record.threatName.size());

                std::vector<unsigned char> body;
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.rawSigLen), reinterpret_cast<unsigned char*>(&hdr.rawSigLen) + sizeof(hdr.rawSigLen));
                body.insert(body.end(), record.rawSignature.begin(), record.rawSignature.end());
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.offsetBegin), reinterpret_cast<unsigned char*>(&hdr.offsetBegin) + sizeof(hdr.offsetBegin));
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.offsetEnd), reinterpret_cast<unsigned char*>(&hdr.offsetEnd) + sizeof(hdr.offsetEnd));
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.objectType), reinterpret_cast<unsigned char*>(&hdr.objectType) + sizeof(hdr.objectType));
                const auto* threatBytes = reinterpret_cast<const unsigned char*>(record.threatName.data());
                body.insert(body.end(), threatBytes, threatBytes + record.threatName.size() * sizeof(wchar_t));

                std::vector<unsigned char> recordSig = sign(body);
                if (recordSig.size() == kSigSize) {
                    memcpy(hdr.recordSig, recordSig.data(), kSigSize);
                }

                recordsBlob.insert(recordsBlob.end(), reinterpret_cast<unsigned char*>(&hdr), reinterpret_cast<unsigned char*>(&hdr) + sizeof(hdr));
                recordsBlob.insert(recordsBlob.end(), record.rawSignature.begin(), record.rawSignature.end());
                recordsBlob.insert(recordsBlob.end(), threatBytes, threatBytes + record.threatName.size() * sizeof(wchar_t));
            }

            std::vector<unsigned char> recordsDigest;
            ComputeSha256(recordsBlob, &recordsDigest);

            Manifest manifest{};
            manifest.magic = kMagic;
            manifest.version = kVersion;
            manifest.recordCount = static_cast<unsigned long>(g_flat_records.size());
            manifest.releaseDateUnix = static_cast<unsigned long long>(time(nullptr));
            if (recordsDigest.size() == 32) {
                memcpy(manifest.recordsDigest, recordsDigest.data(), 32);
            }

            std::vector<unsigned char> manifestPayload(
                reinterpret_cast<unsigned char*>(&manifest),
                reinterpret_cast<unsigned char*>(&manifest) + sizeof(Manifest) - 32
            );
            std::vector<unsigned char> manifestSig = sign(manifestPayload);
            if (manifestSig.size() == kSigSize) {
                memcpy(manifest.manifestSig, manifestSig.data(), kSigSize);
            }

            std::ofstream recOut(recordsPath, std::ios::binary | std::ios::trunc);
            recOut.write(reinterpret_cast<const char*>(recordsBlob.data()), static_cast<std::streamsize>(recordsBlob.size()));
            recOut.close();

            std::ofstream manOut(manifestPath, std::ios::binary | std::ios::trunc);
            manOut.write(reinterpret_cast<const char*>(&manifest), sizeof(manifest));
            manOut.close();
        };

        auto loadFromFiles = [&](const std::filesystem::path& manPath, const std::filesystem::path& recPath, bool allowRecordSkip) {
            std::ifstream manIn(manPath, std::ios::binary);
            std::ifstream recIn(recPath, std::ios::binary);
            if (!manIn.good() || !recIn.good()) {
                return false;
            }

            Manifest manifest{};
            manIn.read(reinterpret_cast<char*>(&manifest), sizeof(manifest));
            if (!manIn.good() || manifest.magic != kMagic || manifest.version != kVersion) {
                return false;
            }

            std::vector<unsigned char> manifestPayload(
                reinterpret_cast<unsigned char*>(&manifest),
                reinterpret_cast<unsigned char*>(&manifest) + sizeof(Manifest) - 32
            );
            std::vector<unsigned char> manifestSig = sign(manifestPayload);
            if (manifestSig.size() != 32 || memcmp(manifestSig.data(), manifest.manifestSig, 32) != 0) {
                return false;
            }

            std::vector<unsigned char> recordsBlob((std::istreambuf_iterator<char>(recIn)), std::istreambuf_iterator<char>());
            std::vector<unsigned char> recordsDigest;
            ComputeSha256(recordsBlob, &recordsDigest);
            if (recordsDigest.size() != 32 || memcmp(recordsDigest.data(), manifest.recordsDigest, 32) != 0) {
                return false;
            }

            g_database.clear();
            g_flat_records.clear();
            g_aho_nodes.clear();

            size_t offset = 0;
            while (offset + sizeof(RecordHdr) <= recordsBlob.size()) {
                RecordHdr hdr{};
                memcpy(&hdr, recordsBlob.data() + offset, sizeof(hdr));
                offset += sizeof(hdr);

                const size_t threatBytes = static_cast<size_t>(hdr.threatNameLen) * sizeof(wchar_t);
                if (offset + hdr.rawSigLen + threatBytes > recordsBlob.size()) {
                    break;
                }

                std::vector<unsigned char> rawSig(
                    recordsBlob.begin() + static_cast<long long>(offset),
                    recordsBlob.begin() + static_cast<long long>(offset + hdr.rawSigLen)
                );
                offset += hdr.rawSigLen;

                const wchar_t* threatPtr = reinterpret_cast<const wchar_t*>(recordsBlob.data() + offset);
                std::wstring threatName(threatPtr, threatPtr + hdr.threatNameLen);
                offset += threatBytes;

                std::vector<unsigned char> body;
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.rawSigLen), reinterpret_cast<unsigned char*>(&hdr.rawSigLen) + sizeof(hdr.rawSigLen));
                body.insert(body.end(), rawSig.begin(), rawSig.end());
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.offsetBegin), reinterpret_cast<unsigned char*>(&hdr.offsetBegin) + sizeof(hdr.offsetBegin));
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.offsetEnd), reinterpret_cast<unsigned char*>(&hdr.offsetEnd) + sizeof(hdr.offsetEnd));
                body.insert(body.end(), reinterpret_cast<unsigned char*>(&hdr.objectType), reinterpret_cast<unsigned char*>(&hdr.objectType) + sizeof(hdr.objectType));
                const auto* tBytes = reinterpret_cast<const unsigned char*>(threatName.data());
                body.insert(body.end(), tBytes, tBytes + threatName.size() * sizeof(wchar_t));

                std::vector<unsigned char> expectedSig = sign(body);
                if (expectedSig.size() != 32 || memcmp(expectedSig.data(), hdr.recordSig, 32) != 0) {
                    if (allowRecordSkip) {
                        continue;
                    }
                    return false;
                }

                AvRecord record{};
                record.rawSignature = std::move(rawSig);
                record.objectSignaturePrefix = ReadPrefixFromBytes(record.rawSignature, 0);
                record.objectSignatureLength = static_cast<unsigned long>(record.rawSignature.size());
                record.offsetBegin = hdr.offsetBegin;
                record.offsetEnd = hdr.offsetEnd;
                record.objectType = static_cast<AvObjectType>(hdr.objectType);
                record.threatName = threatName;
                ComputeSha256(record.rawSignature, &record.objectSignature);
                ComputeRecordSignature(record, &record.avRecordSignature);
                AddRecordUnlocked(record);
            }

            BuildAhoCorasickUnlocked();
            g_database_loaded = !g_flat_records.empty();
            g_release_date = L"disk-db";
            return g_database_loaded;
        };

        auto loadDefaults = [&]() {
            g_database.clear();
            g_flat_records.clear();
            g_aho_nodes.clear();

            AddRecordUnlocked(MakeRecord("WITCHER_SCRIPT_TEST_MALWARE", 0, kDefaultOffsetEnd, AvObjectType::PowerShellScript, L"Witcher.Test.PowerShell"));
            AddRecordUnlocked(MakeRecord("WITCHER_JS_TEST_MALWARE", 0, kDefaultOffsetEnd, AvObjectType::JavaScript, L"Witcher.Test.JavaScript"));
            AddRecordUnlocked(MakeRecord("WITCHER_PE_TEST_MALWARE", 0, kDefaultOffsetEnd, AvObjectType::PeFile, L"Witcher.Test.PE"));
            AddRecordUnlocked(MakeRecord("WITCHER_PY_TEST_MALWARE", 0, kDefaultOffsetEnd, AvObjectType::PythonScript, L"Witcher.Test.Python"));

            BuildAhoCorasickUnlocked();
            g_database_loaded = true;
            g_release_date = L"default-db";
            writeCurrentToFiles();
        };

        if (loadFromFiles(manifestPath, recordsPath, true)) {
            return true;
        }

        if (loadFromFiles(backupManifestPath, backupRecordsPath, true)) {
            writeCurrentToFiles();
            return true;
        }

        loadDefaults();
        return true;
    }

    bool UpdateDatabaseFromServer() {
        std::error_code ec;

        auto moduleDir = []() {
            wchar_t path[MAX_PATH]{};
            GetModuleFileNameW(nullptr, path, MAX_PATH);
            return std::filesystem::path(path).parent_path();
        };

        auto downloadBinary = [&](const wchar_t* endpoint, std::string* out) -> bool {
            if (!out) { return false; }
            out->clear();

            HINTERNET session = WinHttpOpen(L"WitcherTrayService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!session) { return false; }
            HINTERNET connect = WinHttpConnect(session, L"localhost", 8443, 0);
            if (!connect) { WinHttpCloseHandle(session); return false; }
            HINTERNET request = WinHttpOpenRequest(connect, L"GET", endpoint, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!request) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return false; }

            DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

            if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
                !WinHttpReceiveResponse(request, nullptr)) {
                WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return false;
            }

            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX) || statusCode != 200) {
                WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return false;
            }

            while (true) {
                DWORD availableSize = 0;
                if (!WinHttpQueryDataAvailable(request, &availableSize) || availableSize == 0) {
                    break;
                }

                std::string chunk(availableSize, '\0');
                DWORD downloadedSize = 0;
                if (!WinHttpReadData(request, chunk.data(), availableSize, &downloadedSize)) {
                    break;
                }
                chunk.resize(downloadedSize);
                *out += chunk;
            }

            WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
            return !out->empty();
        };

        const auto baseDir = moduleDir();
        const auto manifestPath = baseDir / L"av_manifest.bin";
        const auto recordsPath = baseDir / L"av_records.bin";
        const auto backupManifestPath = baseDir / L"av_manifest.bak";
        const auto backupRecordsPath = baseDir / L"av_records.bak";

        if (std::filesystem::exists(manifestPath, ec)) {
            std::filesystem::copy_file(manifestPath, backupManifestPath, std::filesystem::copy_options::overwrite_existing, ec);
        }
        if (std::filesystem::exists(recordsPath, ec)) {
            std::filesystem::copy_file(recordsPath, backupRecordsPath, std::filesystem::copy_options::overwrite_existing, ec);
        }

        std::string manifestBytes;
        std::string recordBytes;
        if (downloadBinary(L"/api/avdb/manifest", &manifestBytes) && downloadBinary(L"/api/avdb/records", &recordBytes)) {
            std::ofstream manOut(manifestPath, std::ios::binary | std::ios::trunc);
            manOut.write(manifestBytes.data(), static_cast<std::streamsize>(manifestBytes.size()));
            manOut.close();

            std::ofstream recOut(recordsPath, std::ios::binary | std::ios::trunc);
            recOut.write(recordBytes.data(), static_cast<std::streamsize>(recordBytes.size()));
            recOut.close();
        }

        if (LoadDatabaseOnServiceStart()) {
            return true;
        }

        if (std::filesystem::exists(backupManifestPath, ec) && std::filesystem::exists(backupRecordsPath, ec)) {
            std::filesystem::copy_file(backupManifestPath, manifestPath, std::filesystem::copy_options::overwrite_existing, ec);
            std::filesystem::copy_file(backupRecordsPath, recordsPath, std::filesystem::copy_options::overwrite_existing, ec);
            return LoadDatabaseOnServiceStart();
        }

        return LoadDefaultDatabase();
    }
    bool ForceUpdateDatabaseFromServer() {
        return UpdateDatabaseFromServer();
    }
}
