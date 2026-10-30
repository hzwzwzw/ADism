// SPDX-License-Identifier: GPL-3.0-only
// Explicit administrator lab test: creates only fresh GUID empty workspace directories,
// uses a nonexistent WIM, and checks failure cleanup. Does not mount or service any image.
#include "cbs_source_mount.h"
#include <windows.h>
#include <iostream>
#include <vector>
int wmain() {
    std::atomic_bool cancel{false};
    int cases = 0, failures = 0;
    auto check = [&](bool ok, const char *name) {
        ++cases;
        std::cout << name << '=' << ok << std::endl;
        if (!ok)
            ++failures;
    };
    for (const auto &bad : {L"C:\\bad", L"\\\\server\\share", L"\\\\.\\PhysicalDrive0"}) {
        servicing::OwnedRepairMount mount;
        auto hr = mount.Open(L"absent.wim", 1, cancel, {}, bad);
        check(hr != S_OK && !mount.ErrorDetail().empty() && mount.Close() == S_OK,
              "invalid-work-root-rejected");
    }
    wchar_t win[32768]{};
    if (!GetWindowsDirectoryW(win, 32768))
        return 2;
    std::wstring root(win, 3), created;
    GUID id{};
    CoCreateGuid(&id);
    wchar_t guid[40]{};
    StringFromGUID2(id, guid, 40);
    const auto absent = root + L"ADism-Absent-" + guid + L".wim";
    if (GetFileAttributesW(absent.c_str()) != INVALID_FILE_ATTRIBUTES)
        return 2;
    std::vector<wchar_t> previous(32768);
    DWORD n = GetEnvironmentVariableW(L"TEMP", previous.data(), DWORD(previous.size()));
    SetEnvironmentVariableW(L"TEMP", L"Z:\\ADism-invalid-temp");
    servicing::OwnedRepairMount mount;
    auto hr = mount.Open(
        absent, 1, cancel,
        [&](int, const std::wstring &s) {
            const std::wstring prefix = L"正在准备独占的只读修复来源挂载：";
            if (s.rfind(prefix, 0) == 0)
                created = s.substr(prefix.size());
        },
        root);
    SetEnvironmentVariableW(L"TEMP", n && n < previous.size() ? previous.data() : nullptr);
    check(hr != S_OK && !created.empty() && created.rfind(root, 0) == 0, "explicit-root-used-not-TEMP");
    check(mount.ErrorDetail().find(L"打开修复 WIM") != std::wstring::npos, "failure-stage-preserved");
    auto parent = created.empty() ? L"" : created.substr(0, created.find_last_of(L'\\'));
    check(!created.empty() && GetFileAttributesW(parent.c_str()) == INVALID_FILE_ATTRIBUTES &&
              mount.Close() == S_OK,
          "own-empty-workspace-cleaned");
    cancel = true;
    servicing::OwnedRepairMount stopped;
    check(stopped.Open(absent, 1, cancel, {}, root) == HRESULT_FROM_WIN32(ERROR_CANCELLED),
          "pre-cancel-no-workspace");
    std::cout << "cases=" << cases << " failures=" << failures << std::endl;
    return failures ? 1 : 0;
}
