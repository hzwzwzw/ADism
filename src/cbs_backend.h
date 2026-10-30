// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <atomic>
#include <functional>
#include <string>

namespace servicing {
enum class CbsOperation { Scan, Restore };
enum class RepairSourceKind { Default, Directory, Wim, WindowsUpdate, LocalOnly };
struct CbsOptions {
    bool online = true;
    std::wstring root;
    CbsOperation operation = CbsOperation::Scan;
    bool fullPayloadCheck = true; // Explicit manual maintenance; false selects automatic compatibility mode.
    RepairSourceKind sourceKind = RepairSourceKind::Default;
    std::wstring source;
    unsigned sourceIndex = 0;
};
struct CbsResult {
    HRESULT hr = E_FAIL;
    unsigned long requiredAction = 0;
    bool requiredActionAvailable = false;
    int health = -1;
    bool cancelRequested = false;
    bool imageStateUnknown = false;
    std::wstring stage;
    std::wstring detail;
    std::wstring cbsLog;
};
using CbsProgress = std::function<void(int, const std::wstring &)>;
// Invoke only inside the isolated worker process. Uses private x64 CBS interfaces.
CbsResult RunCbs(const CbsOptions &, std::atomic_bool &cancel, const CbsProgress &);
// In-memory fake interfaces only: never opens CBS, mounts hives, or modifies Windows.
int CbsSelfTest();
} // namespace servicing
