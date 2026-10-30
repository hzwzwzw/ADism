// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
namespace servicing {
// Owns only the fresh GUID source mount it creates. Never adopts user mounts.
class OwnedRepairMount {
  public:
    OwnedRepairMount();
    ~OwnedRepairMount();
    OwnedRepairMount(const OwnedRepairMount &) = delete;
    OwnedRepairMount &operator=(const OwnedRepairMount &) = delete;
    HRESULT Open(const std::wstring &wim, unsigned index, std::atomic_bool &cancel,
                 const std::function<void(int, const std::wstring &)> &progress,
                 const std::wstring &workRoot = L"");
    HRESULT Close();
    std::wstring Windows() const;
    const std::wstring &Path() const;
    const std::wstring &ErrorDetail() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace servicing
