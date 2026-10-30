// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <string>
namespace servicing {
struct LocalRoot {
    std::wstring root, volume, filesystem;
    DWORD disk = 0, partition = 0, style = 0;
    bool readOnly = false, active = false;
    BYTE mbrType = 0;
    GUID gptType{};
};
bool DriveRootSyntax(const std::wstring &);
bool OrdinaryPath(const std::wstring &);
HRESULT InspectRoot(const std::wstring &, LocalRoot &);
HRESULT ValidateDeploymentDisk(const std::wstring &, std::wstring &);
HRESULT ValidateEmptyDestination(const std::wstring &, std::wstring &);
HRESULT TrustedMicrosoftTool(const std::wstring &);
class MaintenanceLock {
    HANDLE handle_ = nullptr;
    bool owned_ = false;
    HRESULT hr_ = E_FAIL;

  public:
    explicit MaintenanceLock(const wchar_t *name = L"Global\\ADism.SystemMaintenance");
    ~MaintenanceLock();
    HRESULT Result() const {
        return hr_;
    }
};
int SafetySelfTest();
} // namespace servicing
