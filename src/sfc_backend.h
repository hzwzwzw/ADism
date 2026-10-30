// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <vector>
#include <utility>
namespace servicing {
enum class SfcOperation { Verify, Repair };
enum class SfcReport { Unknown, Clean, Repaired, Unrepaired, Unable };
struct SfcOptions {
    bool online = true;
    std::wstring root; // Offline /offwindir and /offbootdir both derive from this validated root.
    SfcOperation operation = SfcOperation::Verify;
};
struct SfcResult {
    HRESULT hr = E_FAIL;
    DWORD exitCode = 0;
    bool started = false, processExited = false, stopRequested = false;
    SfcReport report = SfcReport::Unknown;
    std::wstring stage, detail, rawLog, textLog, offLog;
};
using SfcProgress = std::function<void(int, const std::wstring &)>;
SfcResult ValidateSfcTarget(const SfcOptions &);
// Isolated worker only. After child creation, stop records intent and waits for
// natural exit; it never interrupts servicing or kills the process.
SfcResult RunSfc(const SfcOptions &, std::atomic_bool &stop, const SfcProgress &);
std::wstring SfcReportText(SfcReport);
HRESULT HostBootPartitions(std::vector<std::pair<DWORD, DWORD>> &);
int SfcSelfTest();
} // namespace servicing
