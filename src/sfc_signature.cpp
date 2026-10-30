// SPDX-License-Identifier: GPL-3.0-only
#include "sfc_signature.h"
#include "safety.h"
#include "win_util.h"
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <vector>
namespace servicing {
namespace {
struct FilePin {
    HANDLE h;
    explicit FilePin(const std::wstring &path)
        : h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) {}
    ~FilePin() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};
HRESULT CatalogMember(const std::wstring &path, HANDLE file, const std::wstring &catalog, HCATADMIN admin,
                      std::vector<BYTE> &hash, const std::wstring &tag) {
    if (!OrdinaryPath(catalog))
        return E_ACCESSDENIED;
    FilePin pin(catalog);
    if (pin.h == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());
    WINTRUST_CATALOG_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszCatalogFilePath = catalog.c_str();
    info.pcwszMemberTag = tag.c_str();
    info.pcwszMemberFilePath = path.c_str();
    info.hMemberFile = file;
    info.pbCalculatedFileHash = hash.data();
    info.cbCalculatedFileHash = DWORD(hash.size());
    info.hCatAdmin = admin;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &data);
    bool microsoft = false;
    if (!status) {
        auto provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        auto signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain) {
            wchar_t name[512]{};
            CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name,
                               512);
            microsoft = !_wcsicmp(name, L"Microsoft Windows") ||
                        !_wcsicmp(name, L"Microsoft Windows Publisher") ||
                        !_wcsicmp(name, L"Microsoft Corporation");
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return status      ? (status < 0 ? HRESULT(status) : HRESULT_FROM_WIN32(DWORD(status)))
           : microsoft ? S_OK
                       : TRUST_E_SUBJECT_NOT_TRUSTED;
}
} // namespace
HRESULT VerifySfcSignature(const std::wstring &path, HANDLE file, const std::wstring &systemDirectory,
                           std::wstring &evidence) {
    HRESULT embedded = TrustedMicrosoftTool(path);
    if (embedded == S_OK) {
        evidence = L"内嵌微软签名";
        return S_OK;
    }
    if (embedded != TRUST_E_NOSIGNATURE)
        return embedded;
    // These catalog reader exports are resolved explicitly for SDK import-library compatibility.
    HMODULE trust = GetModuleHandleW(L"wintrust.dll");
    auto open = LoadFunction<decltype(&CryptCATOpen)>(trust, "CryptCATOpen");
    auto memberInfo = LoadFunction<decltype(&CryptCATGetMemberInfo)>(trust, "CryptCATGetMemberInfo");
    auto closeCatalog = LoadFunction<decltype(&CryptCATClose)>(trust, "CryptCATClose");
    if (!open || !memberInfo || !closeCatalog)
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    const ULONGLONG deadline = GetTickCount64() + 30000;
    // Standard target catalog locations only. Never register target catalogs in the host database.
    const auto windows = systemDirectory.substr(0, systemDirectory.find_last_of(L'\\'));
    std::vector<std::wstring> directories = {systemDirectory +
                                                 L"\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
                                             windows + L"\\WinSxS\\Catalogs"};
    for (const auto algorithm : {L"SHA256", L"SHA1"}) {
        HCATADMIN admin = nullptr;
        if (!CryptCATAdminAcquireContext2(&admin, nullptr, algorithm, nullptr, 0))
            continue;
        struct AdminEnd {
            HCATADMIN h;
            ~AdminEnd() {
                CryptCATAdminReleaseContext(h, 0);
            }
        } end{admin};
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
            return HRESULT_FROM_WIN32(GetLastError());
        DWORD size = 0;
        CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, nullptr, 0);
        if (!size || size > 128)
            continue;
        std::vector<BYTE> hash(size);
        if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, hash.data(), 0))
            continue;
        hash.resize(size);
        std::wstring tag;
        for (BYTE b : hash) {
            tag += L"0123456789ABCDEF"[b >> 4];
            tag += L"0123456789ABCDEF"[b & 15];
        }
        auto registered = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), size, 0, nullptr);
        if (registered) {
            CATALOG_INFO info{};
            info.cbStruct = sizeof(info);
            bool found = CryptCATCatalogInfoFromContext(registered, &info, 0) &&
                         CatalogMember(path, file, info.wszCatalogFile, admin, hash, tag) == S_OK;
            CryptCATAdminReleaseCatalogContext(admin, registered, 0);
            if (found) {
                evidence = L"微软目录签名：" + std::wstring(info.wszCatalogFile);
                return S_OK;
            }
        }
        for (const auto &directory : directories) {
            if (!OrdinaryPath(directory))
                continue;
            WIN32_FIND_DATAW row{};
            HANDLE search = FindFirstFileW((directory + L"\\*.cat").c_str(), &row);
            if (search == INVALID_HANDLE_VALUE)
                continue;
            struct FindEnd {
                HANDLE h;
                ~FindEnd() {
                    FindClose(h);
                }
            } close{search};
            unsigned count = 0;
            do {
                if (GetTickCount64() >= deadline || ++count > 20000)
                    return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                if (row.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                    continue;
                auto catalog = directory + L"\\" + row.cFileName;
                if (!OrdinaryPath(catalog))
                    continue;
                FilePin pin(catalog);
                if (pin.h == INVALID_HANDLE_VALUE)
                    continue;
                HANDLE cat = open(catalog.data(), CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
                if (cat == INVALID_HANDLE_VALUE)
                    continue;
                bool member = memberInfo(cat, tag.data()) != nullptr;
                closeCatalog(cat);
                if (member && CatalogMember(path, file, catalog, admin, hash, tag) == S_OK) {
                    evidence = L"目标系统微软目录签名：" + catalog;
                    return S_OK;
                }
            } while (FindNextFileW(search, &row));
        }
    }
    return TRUST_E_NOSIGNATURE;
}
} // namespace servicing
