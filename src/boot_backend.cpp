// SPDX-License-Identifier: GPL-3.0-only
#include "boot_backend.h"
#include "safety.h"
#include <winioctl.h>
#include <filesystem>
#include <shellapi.h>
#include <vector>
#include <winver.h>
#include <wintrust.h>
namespace servicing {
namespace {
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Handle() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};
HRESULT Error(DWORD n = GetLastError()) {
    return HRESULT_FROM_WIN32(n ? n : ERROR_GEN_FAILURE);
}
std::wstring Quote(const std::wstring &s) {
    return L"\"" + s + L"\"";
}
std::wstring SystemTool(const wchar_t *name) {
    wchar_t dir[32768]{};
    auto n = GetSystemDirectoryW(dir, 32768);
    return n && n < 32768 ? std::wstring(dir) + L"\\" + name : L"";
}
HRESULT ValidateBootsect(const std::wstring &path) {
    if (_wcsicmp(std::filesystem::path(path).filename().c_str(), L"bootsect.exe"))
        return E_INVALIDARG;
    auto hr = TrustedMicrosoftTool(path);
    if (hr != S_OK)
        return hr;
    DWORD ignored = 0, n = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!n || n > 1048576)
        return E_INVALIDARG;
    std::vector<BYTE> data(n);
    if (!GetFileVersionInfoW(path.c_str(), 0, n, data.data()))
        return E_INVALIDARG;
    struct Translation {
        WORD language, codepage;
    };
    Translation *translations = nullptr;
    UINT size = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void **>(&translations),
                        &size) ||
        size % sizeof(Translation) || size > 256)
        return E_INVALIDARG;
    for (UINT i = 0; i < size / sizeof(Translation); ++i) {
        wchar_t key[128]{};
        swprintf(key, 128, L"\\StringFileInfo\\%04x%04x\\OriginalFilename", translations[i].language,
                 translations[i].codepage);
        wchar_t *value = nullptr;
        UINT length = 0;
        if (VerQueryValueW(data.data(), key, reinterpret_cast<void **>(&value), &length) && length &&
            length < 256 && wmemchr(value, 0, length) && !_wcsicmp(value, L"bootsect.exe"))
            return S_OK;
    }
    return TRUST_E_SUBJECT_NOT_TRUSTED;
}
std::wstring Bootsect(const WimOptions &o) {
    if (!o.bootCodeTool.empty()) {
        wchar_t path[32768]{};
        auto n = GetFullPathNameW(o.bootCodeTool.c_str(), 32768, path, nullptr);
        return n && n < 32768 ? path : L"";
    }
    auto system = SystemTool(L"bootsect.exe");
    if (OrdinaryPath(system))
        return system;
    // Installation DVD/ISO, never search PATH or a writable working directory.
    auto media = std::filesystem::path(o.source).root_path().wstring();
    if (!media.empty() && GetDriveTypeW(media.c_str()) == DRIVE_CDROM) {
        auto path = media + L"boot\\bootsect.exe";
        if (OrdinaryPath(path))
            return path;
    }
    return {};
}
std::wstring BcdCommand(const WimOptions &o, int mode) {
    return Quote(SystemTool(L"bcdboot.exe")) + L" " + Quote(o.destination.substr(0, 2) + L"\\Windows") +
           L" /s " + o.bootPartition.substr(0, 2) + L" /f " + (mode == 1 ? L"BIOS" : L"UEFI") + L" /v";
}
std::wstring SectorCommand(const std::wstring &tool, const WimOptions &o) {
    return Quote(tool) + L" /nt60 " + o.bootPartition.substr(0, 2) + L" /mbr";
}
HRESULT RunTool(const std::wstring &exe, std::wstring command, const WimProgress &progress) {
    if (progress)
        progress(-1, L"执行 Windows 引导工具：" + command);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &startup, &process))
        return Error();
    Handle p{process.hProcess}, t{process.hThread};
    if (WaitForSingleObject(p.h, INFINITE) != WAIT_OBJECT_0)
        return Error();
    DWORD exit = 1;
    if (!GetExitCodeProcess(p.h, &exit))
        return Error();
    if (progress)
        progress(-1, L"Windows 引导工具退出码：" + std::to_wstring(exit));
    return exit ? HRESULT_FROM_WIN32(exit) : S_OK;
}
} // namespace
WimResult ValidateBoot(const WimOptions &o) {
    WimResult r;
    r.stage = L"验证启动分区";
    auto fail = [&](HRESULT h, const std::wstring &t) {
        r.hr = h;
        r.detail = t;
        return r;
    };
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"))
        return fail(E_NOTIMPL, L"Wine 不执行引导写入。");
    LocalRoot target, boot;
    HRESULT hr = InspectRoot(o.destination, target);
    if (hr != S_OK)
        return fail(hr, L"无法识别映像目标分区。");
    hr = InspectRoot(o.bootPartition, boot);
    if (hr != S_OK)
        return fail(hr, L"无法识别启动分区；必须是实际本地基本分区。");
    std::wstring detail;
    hr = ValidateDeploymentDisk(target.root, detail);
    if (hr != S_OK)
        return fail(hr, detail);
    if (boot.disk != target.disk)
        return fail(E_INVALIDARG, L"系统与引导分区必须位于同一个独立目标磁盘。");
    if (boot.readOnly || target.readOnly)
        return fail(E_ACCESSDENIED, L"系统或引导分区只读。");
    if (o.firmware < 0 || o.firmware > 2)
        return fail(E_INVALIDARG, L"未知引导模式。");
    int mode = o.firmware ? o.firmware : (target.style == PARTITION_STYLE_GPT ? 2 : 1);
    if (target.style != boot.style || (mode == 1 && target.style != PARTITION_STYLE_MBR) ||
        (mode == 2 && target.style != PARTITION_STYLE_GPT))
        return fail(E_INVALIDARG, L"分区样式必须匹配所选 BIOS/UEFI 模式。");
    if (mode == 2) {
        const GUID efi = {0xc12a7328, 0xf81f, 0x11d2, {0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}};
        if (_wcsicmp(boot.filesystem.c_str(), L"FAT32") || !IsEqualGUID(boot.gptType, efi))
            return fail(E_INVALIDARG, L"UEFI 引导分区必须是已准备好的 FAT32 EFI 系统分区。");
    }
    if (mode == 1) {
        if (!boot.active || boot.partition > 4 || boot.mbrType == 5 || boot.mbrType == 15 ||
            boot.mbrType == 0x85)
            return fail(E_INVALIDARG, L"BIOS 引导分区必须预先准备为活动主分区；ADism 不会修改活动分区标记。");
        auto tool = Bootsect(o);
        if (tool.empty())
            return fail(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
                        L"BIOS 引导需要微软 bootsect.exe。请从 Windows 安装介质选择该工具，或在包含它的 "
                        L"Windows PE 中运行。");
        hr = ValidateBootsect(tool);
        if (hr != S_OK)
            return fail(hr, L"无法验证 bootsect.exe 的微软签名。不会使用未验证的引导工具。");
    }
    if (!OrdinaryPath(SystemTool(L"bcdboot.exe")))
        return fail(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), L"缺少系统目录中的 BCDBoot。");
    r.hr = S_OK;
    return r;
}
WimResult WriteBoot(const WimOptions &o, const WimProgress &progress) {
    auto r = ValidateBoot(o);
    if (r.hr != S_OK)
        return r;
    r.stage = L"写入引导";
    r.partialChanges = true;
    LocalRoot target, boot;
    if (InspectRoot(o.destination, target) != S_OK || InspectRoot(o.bootPartition, boot) != S_OK) {
        r.hr = E_INVALIDARG;
        r.detail = L"执行前无法重新核对分区。";
        return r;
    }
    int mode = o.firmware ? o.firmware : (target.style == PARTITION_STYLE_GPT ? 2 : 1);
    if (!OrdinaryPath(target.root + L"Windows\\System32\\Config\\SYSTEM") ||
        !OrdinaryPath(target.root + L"Windows\\Boot")) {
        r.hr = E_ACCESSDENIED;
        r.detail = L"目标 Windows 关键路径无效或经过重解析点。";
        return r;
    }
    // Keep tool bytes pinned from signature validation through its natural exit.
    std::wstring sectorTool;
    Handle pinned;
    if (mode == 1) {
        sectorTool = Bootsect(o);
        pinned.h = CreateFileW(sectorTool.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0,
                               nullptr);
        if (pinned.h == INVALID_HANDLE_VALUE || ValidateBootsect(sectorTool) != S_OK) {
            r.hr = E_ACCESSDENIED;
            r.detail = L"无法保持并验证微软引导工具，未执行引导写入。";
            return r;
        }
    }
    auto command = BcdCommand(o, mode);
    r.hr = RunTool(SystemTool(L"bcdboot.exe"), command, progress);
    if (r.hr != S_OK) {
        r.detail = L"BCDBoot 未完成；目标可能已写入部分引导文件。不会删除现有 Boot/EFI 目录后重试。";
        return r;
    }
    if (mode == 1) {
        r.hr = RunTool(sectorTool, SectorCommand(sectorTool, o), progress);
        if (r.hr != S_OK) {
            r.detail =
                L"BCDBoot 已返回成功，但 bootsect 未完成。目标可能已有部分修改；未使用 /force 强制卸载卷。";
            return r;
        }
    }
    r.hr = S_OK;
    r.partialChanges = false;
    r.detail =
        mode == 1
            ? L"微软 BCDBoot 与 bootsect 已返回成功；请在目标设备验证启动。"
            : L"UEFI "
              L"引导文件已写入指定分区；未创建固件启动项或调整启动顺序。请通过固件启动菜单选择目标设备。";
    return r;
}
int BootSelfTest() {
    WimOptions o;
    o.destination = L"G:\\";
    o.bootPartition = L"S:\\";
    auto command = BcdCommand(o, 2);
    if (command.find(L" /s S: /f UEFI /v") == command.npos || command.find(L"G:\\Windows") == command.npos)
        return 1;
    auto sector = SectorCommand(L"D:\\Tools Folder\\bootsect.exe", o);
    if (sector.find(L" /nt60 S: /mbr") == sector.npos || sector.find(L"/force") != sector.npos ||
        sector.find(L" ALL") != sector.npos || sector.find(L" SYS") != sector.npos)
        return 2;
    return 0;
}
} // namespace servicing
