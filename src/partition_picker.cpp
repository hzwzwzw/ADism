// SPDX-License-Identifier: GPL-3.0-only
#include "partition_picker.h"
#include "ui_log.h"
#include <winioctl.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <objbase.h>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <iomanip>
namespace workbench {
namespace {
struct Handle {
    HANDLE h;
    ~Handle() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
};
std::wstring Guid(const GUID &g) {
    wchar_t b[48]{};
    StringFromGUID2(g, b, 48);
    return b;
}
std::wstring Size(unsigned long long n) {
    std::wostringstream s;
    s << std::fixed << std::setprecision(n >= 1073741824 ? 2 : 0)
      << double(n) / (n >= 1073741824 ? 1073741824 : 1048576) << (n >= 1073741824 ? L" GiB" : L" MiB");
    return s.str();
}
std::wstring ErrorText(DWORD code) {
    wchar_t *p = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<wchar_t *>(&p), 0, nullptr);
    std::wstring s = p ? p : L"操作失败";
    if (p)
        LocalFree(p);
    return s + L" (" + std::to_wstring(code) + L")";
}
bool Equal(const std::wstring &a, const std::wstring &b) {
    return !_wcsicmp(a.c_str(), b.c_str());
}
struct Volume {
    std::wstring name, label, fs, letters;
    DWORD disk;
    LONGLONG offset;
};
std::vector<Volume> Volumes() {
    std::vector<Volume> result;
    wchar_t name[1024]{};
    auto find = FindFirstVolumeW(name, 1024);
    if (find == INVALID_HANDLE_VALUE)
        return result;
    do {
        std::wstring path = name;
        path.pop_back();
        Handle h{CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                             nullptr)};
        struct {
            VOLUME_DISK_EXTENTS e;
            DISK_EXTENT extra[8];
        } ext{};
        DWORD got = 0;
        if (h.h == INVALID_HANDLE_VALUE ||
            !DeviceIoControl(h.h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, &ext, sizeof(ext), &got,
                             nullptr) ||
            ext.e.NumberOfDiskExtents != 1)
            continue;
        Volume v;
        v.name = name;
        v.disk = ext.e.Extents[0].DiskNumber;
        v.offset = ext.e.Extents[0].StartingOffset.QuadPart;
        wchar_t label[1024]{}, fs[64]{};
        // Suppress media error boxes, including locked/removable volumes.
        GetVolumeInformationW(name, label, 1024, nullptr, nullptr, nullptr, fs, 64);
        v.label = label;
        v.fs = fs;
        wchar_t paths[32768]{};
        DWORD needed = 0;
        if (GetVolumePathNamesForVolumeNameW(name, paths, 32768, &needed))
            for (auto p = paths; *p; p += wcslen(p) + 1)
                if (wcslen(p) == 3 && p[1] == L':') {
                    if (!v.letters.empty())
                        v.letters += L" ";
                    v.letters += p;
                }
        result.push_back(std::move(v));
    } while (FindNextVolumeW(find, name, 1024));
    FindVolumeClose(find);
    return result;
}
} // namespace
std::wstring PartitionChoice::Caption() const {
    return L"硬盘 " + std::to_wstring(disk) + L" · 分区 " + std::to_wstring(partition) + L"  |  " +
           Size(bytes) + L"  |  " + (label.empty() ? L"无卷标" : label) + L"  |  " +
           (letters.empty() ? L"无盘符" : letters);
}
std::vector<PartitionChoice> EnumeratePartitions(std::wstring &error) {
    error.clear();
    DWORD old = 0;
    SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &old);
    struct Mode {
        DWORD old;
        ~Mode() {
            SetThreadErrorMode(old, nullptr);
        }
    } mode{old};
    auto volumes = Volumes();
    std::vector<PartitionChoice> result;
    std::vector<wchar_t> devices(65536);
    if (!QueryDosDeviceW(nullptr, devices.data(), DWORD(devices.size()))) {
        error = ErrorText(GetLastError());
        return result;
    }
    for (auto p = devices.data(); *p; p += wcslen(p) + 1) {
        std::wstring device = p;
        const std::wstring prefix = L"PhysicalDrive";
        if (device.compare(0, prefix.size(), prefix) || device.size() == prefix.size() ||
            !std::all_of(device.begin() + prefix.size(), device.end(),
                         [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
            continue;
        DWORD disk = std::stoul(device.substr(prefix.size()));
        Handle h{CreateFileW((L"\\\\.\\" + device).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr)};
        if (h.h == INVALID_HANDLE_VALUE)
            continue;
        std::vector<BYTE> buffer(65536);
        DWORD got = 0;
        if (!DeviceIoControl(h.h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, buffer.data(),
                             DWORD(buffer.size()), &got, nullptr) ||
            got < offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry))
            continue;
        auto layout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX *>(buffer.data());
        if (layout->PartitionCount >
            (got - offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) / sizeof(PARTITION_INFORMATION_EX))
            continue;
        std::wstring diskId = layout->PartitionStyle == PARTITION_STYLE_GPT
                                  ? Guid(layout->Gpt.DiskId)
                                  : L"MBR:" + std::to_wstring(layout->Mbr.Signature);
        std::wstring model;
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::vector<BYTE> desc(4096);
        if (DeviceIoControl(h.h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), desc.data(),
                            DWORD(desc.size()), &got, nullptr) &&
            got >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            auto d = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR *>(desc.data());
            for (DWORD off : {d->VendorIdOffset, d->ProductIdOffset, d->SerialNumberOffset})
                if (off && off < got) {
                    auto s = reinterpret_cast<char *>(desc.data() + off);
                    size_t n = 0;
                    while (off + n < got && s[n])
                        ++n;
                    for (size_t i = 0; i < n; ++i)
                        model += wchar_t(static_cast<unsigned char>(s[i]));
                    model += L" ";
                }
        }
        for (DWORD i = 0; i < layout->PartitionCount; ++i) {
            auto &part = layout->PartitionEntry[i];
            if (!part.PartitionNumber || part.PartitionLength.QuadPart <= 0)
                continue;
            PartitionChoice c;
            c.disk = disk;
            c.partition = part.PartitionNumber;
            c.offset = part.StartingOffset.QuadPart;
            c.bytes = part.PartitionLength.QuadPart;
            c.diskId = diskId;
            c.model = model;
            if (part.PartitionStyle == PARTITION_STYLE_GPT) {
                auto type = Guid(part.Gpt.PartitionType);
                std::wstring role = Equal(type, L"{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}")   ? L"EFI 系统分区"
                                    : Equal(type, L"{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}") ? L"MSR 保留分区"
                                    : Equal(type, L"{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}")
                                        ? L"Windows 恢复分区"
                                    : Equal(type, L"{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}") ? L"基本数据分区"
                                                                                             : L"其他分区";
                c.type = L"GPT · " + role + L" " + type;
            } else
                c.type = L"MBR 类型 " + std::to_wstring(part.Mbr.PartitionType);
            for (const auto &v : volumes)
                if (v.disk == disk && v.offset == part.StartingOffset.QuadPart) {
                    c.volume = v.name;
                    c.label = v.label;
                    c.filesystem = v.fs;
                    c.letters = v.letters;
                    break;
                }
            c.selectable = !c.volume.empty() && !c.filesystem.empty();
            result.push_back(std::move(c));
        }
    }
    std::sort(result.begin(), result.end(), [](const auto &a, const auto &b) {
        return a.disk == b.disk ? a.partition < b.partition : a.disk < b.disk;
    });
    if (result.empty())
        error = L"未发现可查询的硬盘分区。请确认以管理员身份运行。";
    return result;
}
namespace {
struct Picker {
    HWND list = nullptr, detail = nullptr, ok = nullptr;
    std::vector<PartitionChoice> rows;
    PartitionChoice selected;
    bool accepted = false;
};
void Populate(HWND h, Picker &p) {
    std::wstring error;
    p.rows = EnumeratePartitions(error);
    ListView_DeleteAllItems(p.list);
    int n = 0;
    for (const auto &c : p.rows) {
        auto disk = std::to_wstring(c.disk), part = std::to_wstring(c.partition);
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = n;
        item.pszText = disk.data();
        ListView_InsertItem(p.list, &item);
        std::wstring cells[] = {part,
                                c.label.empty() ? L"—" : c.label,
                                Size(c.bytes),
                                c.letters.empty() ? L"无盘符" : c.letters,
                                c.filesystem.empty() ? L"不可用 / 未格式化" : c.filesystem,
                                c.model};
        for (int j = 0; j < 6; ++j)
            ListView_SetItemText(p.list, n, j + 1, cells[j].data());
        ++n;
    }
    EnableWindow(p.ok, FALSE);
    SetWindowTextW(p.detail,
                   error.empty()
                       ? L"选择分区以查看卷标识。无盘符分区将在确认操作后临时分配盘符，任务结束后移除。"
                       : error.c_str());
    (void)h;
}
LRESULT CALLBACK PickerProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto p = reinterpret_cast<Picker *>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        p = static_cast<Picker *>(reinterpret_cast<CREATESTRUCTW *>(l)->lpCreateParams);
        SetWindowLongPtrW(h, GWLP_USERDATA, LONG_PTR(p));
    }
    if (!p)
        return DefWindowProcW(h, m, w, l);
    switch (m) {
    case WM_CREATE: {
        p->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                      LVS_SHOWSELALWAYS,
                                  20, 20, 920, 330, h, HMENU(1), nullptr, nullptr);
        ListView_SetExtendedListViewStyle(p->list,
                                          LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        SetWindowTheme(p->list, L"Explorer", nullptr);
        int widths[] = {65, 65, 145, 110, 100, 145, 260};
        const wchar_t *names[] = {L"硬盘", L"分区", L"卷标", L"容量", L"盘符", L"文件系统", L"设备标识"};
        for (int i = 0; i < 7; ++i) {
            LVCOLUMNW c{};
            c.mask = LVCF_TEXT | LVCF_WIDTH;
            c.pszText = const_cast<wchar_t *>(names[i]);
            c.cx = widths[i];
            ListView_InsertColumn(p->list, i, &c);
        }
        p->detail = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY, 20, 365,
                                  920, 116, h, HMENU(2), nullptr, nullptr);
        p->ok = CreateWindowW(L"BUTTON", L"选择分区", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                              700, 500, 120, 36, h, HMENU(IDOK), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 836, 500, 104, 36, h,
                      HMENU(IDCANCEL), nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"刷新", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 20, 500, 100, 36, h, HMENU(3),
                      nullptr, nullptr);
        auto font =
            reinterpret_cast<HFONT>(SendMessageW(GetDlgItem(GetWindow(h, GW_OWNER), 202), WM_GETFONT, 0, 0));
        if (!font)
            font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        for (auto child = GetWindow(h, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT))
            SendMessageW(child, WM_SETFONT, WPARAM(font), TRUE);
        Populate(h, *p);
        return 0;
    }
    case WM_NOTIFY: {
        auto n = reinterpret_cast<NMHDR *>(l);
        if (n->idFrom == 1 && (n->code == LVN_ITEMCHANGED || n->code == NM_DBLCLK)) {
            int i = ListView_GetNextItem(p->list, -1, LVNI_SELECTED);
            if (i >= 0 && size_t(i) < p->rows.size()) {
                auto &c = p->rows[i];
                EnableWindow(p->ok, c.selectable);
                auto detail =
                    c.Caption() + L"\r\n磁盘标识：" + c.diskId + L"；偏移：" + std::to_wstring(c.offset) +
                    L"；类型：" + c.type + L"\r\n卷：" + (c.volume.empty() ? L"无可访问卷" : c.volume) +
                    (c.selectable
                         ? (c.letters.empty() ? L"\r\n确认操作后临时挂载；不格式化、不修改分区类型。" : L"")
                         : L"\r\n不可选择：无可访问文件系统（可能为 MSR、未格式化、锁定或不支持的卷）。");
                SetWindowTextW(p->detail, detail.c_str());
                if (n->code == NM_DBLCLK && c.selectable)
                    SendMessageW(h, WM_COMMAND, IDOK, 0);
            }
            return 0;
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(w) == 3) {
            Populate(h, *p);
            return 0;
        }
        if (LOWORD(w) == IDOK) {
            int i = ListView_GetNextItem(p->list, -1, LVNI_SELECTED);
            if (i >= 0 && size_t(i) < p->rows.size() && p->rows[i].selectable) {
                p->selected = p->rows[i];
                p->accepted = true;
                DestroyWindow(h);
            }
            return 0;
        }
        if (LOWORD(w) == IDCANCEL) {
            DestroyWindow(h);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
} // namespace
bool PickPartition(HWND owner, PartitionChoice &choice) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW c{};
        c.lpfnWndProc = PickerProc;
        c.hInstance = GetModuleHandleW(nullptr);
        c.lpszClassName = L"ADism.Partitions";
        c.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        c.hbrBackground = HBRUSH(COLOR_WINDOW + 1);
        registered = RegisterClassW(&c) != 0;
        if (!registered)
            return false;
    }
    Picker p;
    RECT r{};
    GetWindowRect(owner, &r);
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    if (GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &monitor)) {
        r.left = std::max(monitor.rcWork.left, std::min(r.left + 20, monitor.rcWork.right - 980));
        r.top = std::max(monitor.rcWork.top, std::min(r.top + 30, monitor.rcWork.bottom - 590));
    }
    auto h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"ADism.Partitions", L"选择硬盘与分区",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, r.left, r.top, 980, 590, owner, nullptr,
                             GetModuleHandleW(nullptr), &p);
    if (!h)
        return false;
    EnableWindow(owner, FALSE);
    ShowWindow(h, SW_SHOW);
    MSG msg{};
    while (IsWindow(h)) {
        int got = GetMessageW(&msg, nullptr, 0, 0);
        if (got <= 0) {
            if (!got)
                PostQuitMessage(int(msg.wParam));
            DestroyWindow(h);
            break;
        }
        if (!IsDialogMessageW(h, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetActiveWindow(owner);
    if (p.accepted)
        choice = p.selected;
    return p.accepted;
}
PartitionAccess::~PartitionAccess() {
    Clear();
}
bool PartitionAccess::Resolve(const PartitionChoice &c, std::wstring &root, std::wstring &error) {
    std::wstring e;
    auto now = EnumeratePartitions(e);
    auto it = std::find_if(now.begin(), now.end(), [&](const auto &v) {
        return v.disk == c.disk && v.partition == c.partition && v.offset == c.offset && v.bytes == c.bytes &&
               Equal(v.diskId, c.diskId) && Equal(v.volume, c.volume) && v.selectable;
    });
    if (it == now.end()) {
        error = L"分区身份或可访问状态已变化，请重新选择：" + c.Caption();
        return false;
    }
    if (!it->letters.empty()) {
        root = it->letters.substr(0, 3);
        wchar_t name[1024]{};
        if (!GetVolumeNameForVolumeMountPointW(root.c_str(), name, 1024) || !Equal(name, c.volume)) {
            error = L"盘符已不再对应所选卷，请重新选择。";
            return false;
        }
        Log(c.Caption() + L"；卷=" + c.volume + L"；路径=" + root, true, L"分区");
        return true;
    }
    for (const auto &m : mounts_)
        if (Equal(m.volume, c.volume)) {
            root = m.root;
            return true;
        }
    for (wchar_t letter = L'Z'; letter >= L'D'; --letter) {
        wchar_t name[32768]{};
        std::wstring drive = std::wstring(1, letter) + L":";
        if (QueryDosDeviceW(drive.c_str(), name, 32768))
            continue;
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            continue;
        root = drive + L"\\";
        if (!SetVolumeMountPointW(root.c_str(), c.volume.c_str())) {
            DWORD code = GetLastError();
            if (code == ERROR_DIR_NOT_EMPTY || code == ERROR_ALREADY_EXISTS)
                continue;
            error = L"无法临时挂载所选分区：" + ErrorText(code);
            return false;
        }
        mounts_.push_back({root, c.volume});
        wchar_t actual[1024]{};
        if (!GetVolumeNameForVolumeMountPointW(root.c_str(), actual, 1024) || !Equal(actual, c.volume)) {
            error = L"临时挂载后卷身份校验失败。";
            Clear();
            return false;
        }
        Log(c.Caption() + L"；卷=" + c.volume + L"；临时路径=" + root, true, L"分区");
        return true;
    }
    error = L"没有可用盘符，无法为此分区建立临时访问路径。";
    return false;
}
void PartitionAccess::Clear() {
    for (auto it = mounts_.begin(); it != mounts_.end();) {
        wchar_t name[1024]{};
        if (!GetVolumeNameForVolumeMountPointW(it->root.c_str(), name, 1024)) {
            if (GetLastError() == ERROR_PATH_NOT_FOUND || GetLastError() == ERROR_FILE_NOT_FOUND) {
                it = mounts_.erase(it);
                continue;
            }
            Log(L"无法核对临时盘符，保留映射：" + it->root, true, L"分区", LogLevel::Warning);
            ++it;
            continue;
        }
        if (!Equal(name, it->volume)) {
            Log(L"临时盘符已被其他卷占用，未移除：" + it->root, true, L"分区", LogLevel::Warning);
            it = mounts_.erase(it);
            continue;
        }
        if (DeleteVolumeMountPointW(it->root.c_str())) {
            Log(L"已移除临时路径：" + it->root + L"；卷=" + it->volume, true, L"分区");
            it = mounts_.erase(it);
        } else {
            Log(L"临时路径移除失败：" + it->root + L"；" + ErrorText(GetLastError()), true, L"分区",
                LogLevel::Warning);
            ++it;
        }
    }
}
} // namespace workbench
