// SPDX-License-Identifier: GPL-3.0-only
#include "safety.h"
#include "sfc_backend.h"
#include <winioctl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <filesystem>
#include <algorithm>
#include <cwctype>
#include <thread>
namespace servicing {
namespace {
HRESULT Error(DWORD n = GetLastError()) {
    return HRESULT_FROM_WIN32(n ? n : ERROR_GEN_FAILURE);
}
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Handle() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};
} // namespace
bool DriveRootSyntax(const std::wstring &p) {
    return (p.size() == 2 || p.size() == 3) &&
           ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) && p[1] == L':' &&
           (p.size() == 2 || p[2] == L'\\');
}
bool OrdinaryPath(const std::wstring &value) {
    if (value.empty() || value.rfind(L"\\\\", 0) == 0)
        return false;
    std::filesystem::path p(value);
    for (; !p.empty();) {
        DWORD a = GetFileAttributesW(p.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_REPARSE_POINT))
            return false;
        auto parent = p.parent_path();
        if (parent == p)
            break;
        p = parent;
    }
    return true;
}
HRESULT InspectRoot(const std::wstring &input, LocalRoot &out) {
    if (!DriveRootSyntax(input))
        return E_INVALIDARG;
    LocalRoot v;
    v.root = std::wstring(1, wchar_t(towupper(input[0]))) + L":\\";
    wchar_t device[32768]{}, volume[1024]{};
    if (!OrdinaryPath(v.root) || !QueryDosDeviceW(v.root.substr(0, 2).c_str(), device, 32768))
        return E_INVALIDARG;
    const std::wstring prefix = L"\\Device\\HarddiskVolume";
    std::wstring path = device;
    if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) ||
        !std::all_of(path.begin() + prefix.size(), path.end(),
                     [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
        return E_INVALIDARG;
    if (!GetVolumeNameForVolumeMountPointW(v.root.c_str(), volume, 1024))
        return Error();
    v.volume = volume;
    Handle h{CreateFileW((L"\\\\.\\" + v.root.substr(0, 2)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, 0, nullptr)};
    if (h.h == INVALID_HANDLE_VALUE)
        return Error();
    STORAGE_DEVICE_NUMBER number{};
    PARTITION_INFORMATION_EX part{};
    struct {
        VOLUME_DISK_EXTENTS ext;
        DISK_EXTENT spare[4];
    } buffer{};
    DWORD n = 0;
    if (!DeviceIoControl(h.h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &number, sizeof(number), &n,
                         nullptr) ||
        n < sizeof(number) || number.DeviceType != FILE_DEVICE_DISK || !number.PartitionNumber ||
        number.PartitionNumber == DWORD(-1))
        return E_INVALIDARG;
    if (!DeviceIoControl(h.h, IOCTL_DISK_GET_PARTITION_INFO_EX, nullptr, 0, &part, sizeof(part), &n,
                         nullptr) ||
        n < sizeof(part) || part.PartitionNumber != number.PartitionNumber)
        return E_INVALIDARG;
    if (!DeviceIoControl(h.h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, &buffer, sizeof(buffer), &n,
                         nullptr) ||
        n < sizeof(VOLUME_DISK_EXTENTS) || buffer.ext.NumberOfDiskExtents != 1 ||
        buffer.ext.Extents[0].DiskNumber != number.DeviceNumber ||
        buffer.ext.Extents[0].StartingOffset.QuadPart != part.StartingOffset.QuadPart ||
        buffer.ext.Extents[0].ExtentLength.QuadPart != part.PartitionLength.QuadPart)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    wchar_t fs[64]{};
    DWORD flags = 0;
    if (!GetVolumeInformationW(v.root.c_str(), nullptr, 0, nullptr, nullptr, &flags, fs, 64))
        return Error();
    v.disk = number.DeviceNumber;
    v.partition = number.PartitionNumber;
    v.style = part.PartitionStyle;
    if (part.PartitionStyle == PARTITION_STYLE_MBR) {
        v.active = part.Mbr.BootIndicator != FALSE;
        v.mbrType = part.Mbr.PartitionType;
    } else if (part.PartitionStyle == PARTITION_STYLE_GPT)
        v.gptType = part.Gpt.PartitionType;
    v.filesystem = fs;
    v.readOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;
    out = std::move(v);
    return S_OK;
}
HRESULT ValidateDeploymentDisk(const std::wstring &root, std::wstring &detail) {
    LocalRoot target;
    HRESULT hr = InspectRoot(root, target);
    if (hr != S_OK) {
        detail = L"目标不是可可靠识别的本地基本分区，或经过重解析/虚拟映射。";
        return hr;
    }
    if (_wcsicmp(target.filesystem.c_str(), L"NTFS")) {
        detail = L"Windows 镜像目标必须是已经准备好的 NTFS 分区。";
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    if (target.readOnly) {
        detail = L"目标分区只读。";
        return E_ACCESSDENIED;
    }
    wchar_t windows[32768]{};
    UINT n = GetWindowsDirectoryW(windows, 32768);
    if (!n || n >= 32768) {
        detail = L"无法识别当前 Windows。";
        return E_INVALIDARG;
    }
    LocalRoot host;
    hr = InspectRoot(std::wstring(windows, 3), host);
    // RAM-based PE has no host disk; boot-partition identity is still mandatory.
    if (hr == S_OK && host.disk == target.disk) {
        detail = L"镜像释放仅允许独立目标磁盘；目标与当前 Windows 位于同一磁盘。";
        return E_ACCESSDENIED;
    }
    if (hr != S_OK) {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\MiniNT", 0, KEY_READ,
                          &key) != ERROR_SUCCESS) {
            detail = L"无法可靠识别当前 Windows 所在磁盘，未执行释放。";
            return hr;
        }
        RegCloseKey(key);
    }
    std::vector<std::pair<DWORD, DWORD>> boot;
    hr = HostBootPartitions(boot);
    if (hr != S_OK) {
        detail = L"无法通过 Windows Storage 服务确认当前启动磁盘，未执行释放；PE 需要相应 Storage/WMI 组件。";
        return hr;
    }
    for (auto p : boot)
        if (p.first == target.disk) {
            detail = L"目标磁盘承载当前实际启动分区，禁止释放镜像或写入引导。";
            return E_ACCESSDENIED;
        }
    return S_OK;
}
HRESULT ValidateEmptyDestination(const std::wstring &root, std::wstring &detail) {
    try {
        for (const auto &e : std::filesystem::directory_iterator(root)) {
            auto name = e.path().filename().wstring();
            std::transform(name.begin(), name.end(), name.begin(), towlower);
            DWORD attr = GetFileAttributesW(e.path().c_str());
            if ((name == L"system volume information" || name == L"$recycle.bin") &&
                attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) &&
                !(attr & FILE_ATTRIBUTE_REPARSE_POINT))
                continue;
            detail =
                L"目标分区不是空白分区。请先备份并自行准备空白目标；ADism 不会迁移、删除或覆盖已有数据。";
            return HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
        }
        return S_OK;
    } catch (...) {
        detail = L"无法完整检查目标分区内容，未执行释放。";
        return E_ACCESSDENIED;
    }
}
HRESULT TrustedMicrosoftTool(const std::wstring &path) {
    if (!OrdinaryPath(path) || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES ||
        (GetFileAttributesW(path.c_str()) & FILE_ATTRIBUTE_DIRECTORY))
        return E_INVALIDARG;
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &data);
    bool microsoft = false;
    if (status == ERROR_SUCCESS) {
        auto provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        auto signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain) {
            wchar_t name[512]{};
            CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name,
                               512);
            microsoft = !_wcsicmp(name, L"Microsoft Windows") || !_wcsicmp(name, L"Microsoft Corporation") ||
                        !_wcsicmp(name, L"Microsoft Windows Publisher");
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return status != ERROR_SUCCESS ? (status < 0 ? HRESULT(status) : HRESULT_FROM_WIN32(DWORD(status))) : microsoft ? S_OK : TRUST_E_SUBJECT_NOT_TRUSTED;
}
MaintenanceLock::MaintenanceLock(const wchar_t *name) {
    handle_ = CreateMutexW(nullptr, FALSE, name);
    if (!handle_) {
        hr_ = Error();
        return;
    }
    DWORD wait = WaitForSingleObject(handle_, 0);
    owned_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    hr_ = wait == WAIT_OBJECT_0    ? S_OK
          : wait == WAIT_TIMEOUT   ? HRESULT_FROM_WIN32(ERROR_BUSY)
          : wait == WAIT_ABANDONED ? HRESULT_FROM_WIN32(ERROR_ABANDONED_WAIT_0)
                                   : Error();
}
MaintenanceLock::~MaintenanceLock() {
    if (owned_)
        ReleaseMutex(handle_);
    if (handle_)
        CloseHandle(handle_);
}
int SafetySelfTest() {
    int n = 0;
    for (auto p : {L"C:", L"g:\\"})
        if (!DriveRootSyntax(p))
            ++n;
    for (auto p : {L"", L"C:relative", L"C:\\Windows", L"\\\\server\\x", L"1:\\", L"C:/", L"C:\\\\"})
        if (DriveRootSyntax(p))
            ++n;
    auto name = L"Local\\ADism.UnitMutex." + std::to_wstring(GetCurrentProcessId());
    {
        MaintenanceLock first(name.c_str());
        if (first.Result() != S_OK)
            ++n;
        HRESULT other = S_OK;
        std::thread contender([&] {
            MaintenanceLock second(name.c_str());
            other = second.Result();
        });
        contender.join();
        if (other != HRESULT_FROM_WIN32(ERROR_BUSY))
            ++n;
    }
    {
        MaintenanceLock again(name.c_str());
        if (again.Result() != S_OK)
            ++n;
    }
    return n;
}
} // namespace servicing
