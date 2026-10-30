// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>
namespace servicing {
struct WimImage {
    unsigned index = 0;
    std::wstring name, description, architecture;
    unsigned major = 0, minor = 0, build = 0, revision = 0;
    std::wstring edition, installationType;
    std::vector<std::wstring> languages;
    uint64_t totalBytes = 0;
};
struct WimOptions {
    std::wstring source, destination, bootPartition, bootCodeTool;
    unsigned imageIndex = 1;
    bool addBoot = false, windowsToGo = false;
    int firmware = 0;
};
struct WimResult {
    HRESULT hr = E_FAIL;
    std::wstring stage, detail;
    bool cancelled = false, partialChanges = false;
};
using WimProgress = std::function<void(int, const std::wstring &)>;
std::vector<WimImage> EnumerateWim(const std::wstring &, WimResult &);
WimResult ApplyWim(const WimOptions &, std::atomic_bool &, const WimProgress &);
int WimSelfTest();
} // namespace servicing
