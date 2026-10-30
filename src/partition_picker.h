// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <string>
#include <vector>
namespace workbench {
struct PartitionChoice {
    DWORD disk = 0, partition = 0;
    unsigned long long offset = 0, bytes = 0;
    std::wstring diskId, volume, label, filesystem, letters, model, type;
    bool selectable = false;
    std::wstring Caption() const;
};
std::vector<PartitionChoice> EnumeratePartitions(std::wstring &error);
bool PickPartition(HWND owner, PartitionChoice &choice);
// Only mount-manager drive letters created by this instance are owned/removed.
class PartitionAccess {
    struct Mount {
        std::wstring root, volume;
    };
    std::vector<Mount> mounts_;

  public:
    ~PartitionAccess();
    bool Resolve(const PartitionChoice &choice, std::wstring &root, std::wstring &error);
    void Clear();
    bool Pending() const {
        return !mounts_.empty();
    }
};
} // namespace workbench
