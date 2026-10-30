// SPDX-License-Identifier: GPL-3.0-only
// Read-only program selection checks. Never starts SFC or invokes maintenance.
#include "../src/sfc_backend.cpp"
#include <iostream>
int wmain() {
    int failures = servicing::SfcSelfTest(), cases = 0;
    auto check = [&](bool ok, const char *name) {
        ++cases;
        std::cout << name << '=' << ok << std::endl;
        if (!ok)
            ++failures;
    };
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version")) {
        std::cout << "native-selection-checks=SKIP (Wine)\n";
        return failures ? 1 : 0;
    }
    wchar_t sys[32768]{};
    UINT size = GetSystemDirectoryW(sys, 32768);
    if (!size || size >= 32768)
        return 2;
    GUID id{};
    if (CoCreateGuid(&id) != S_OK)
        return 2;
    wchar_t suffix[40]{};
    StringFromGUID2(id, suffix, 40);
    // Deliberately nonexistent path: no host file is changed or hidden.
    std::wstring absent = servicing::Join(sys, std::wstring(L"ADism-Missing-") + suffix);
    {
        servicing::SfcTool selected;
        std::wstring detail;
        auto hr = servicing::SelectToolPaths(false, sys, absent, selected, detail);
        check(hr == S_OK && !selected.fallback && selected.exe == servicing::Join(sys, L"sfc.exe"),
              "host-preferred");
    }
    {
        servicing::SfcTool selected;
        std::wstring detail;
        auto hr = servicing::SelectToolPaths(false, absent, sys, selected, detail);
        std::wcout << L"fallback-hr=" << std::hex << unsigned(hr) << L" " << detail << std::endl;
        check(hr == S_OK && selected.fallback && selected.exe == servicing::Join(sys, L"sfc.exe"),
              "missing-host-signed-target-fallback");
    }
    {
        servicing::SfcTool selected;
        std::wstring detail;
        auto hr = servicing::SelectToolPaths(true, absent, sys, selected, detail);
        check(hr != S_OK && !selected.fallback, "online-never-falls-back");
    }
    {
        servicing::SfcTool selected;
        std::wstring detail;
        auto hr = servicing::SelectToolPaths(false, absent, absent, selected, detail);
        check(hr != S_OK && selected.fallback, "both-missing-explicit-failure");
    }
    check(!servicing::OriginalSfc(servicing::Join(sys, L"cmd.exe")), "other-microsoft-tool-not-sfc");
    std::cout << "selection-cases=" << cases << " failures=" << failures << std::endl;
    return failures ? 1 : 0;
}
