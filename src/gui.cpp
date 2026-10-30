// SPDX-License-Identifier: GPL-3.0-only
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include <stdexcept>
#include <uxtheme.h>
#include "ui_log.h"
#include "partition_picker.h"
#include <map>
#include <array>
#include "cbs_backend.h"
#include "sfc_backend.h"
#include "wim_backend.h"
#include "boot_backend.h"
#include "safety.h"

namespace {
constexpr UINT WM_PROGRESS = WM_APP + 1, WM_FINISHED = WM_APP + 2, WM_PHASE = WM_APP + 3;
enum {
    TAB = 100,
    SOURCE = 101,
    LOAD = 102,
    IMAGES = 103,
    DEST = 104,
    BOOT = 105,
    WTG = 106,
    BOOTPART = 107,
    FIRMWARE = 108,
    APPLY = 109,
    CANCEL = 110,
    ONLINE = 201,
    ROOT = 202,
    SCAN = 203,
    RESTORE = 204,
    SOURCE_KIND = 205,
    REPAIR_PATH = 206,
    REPAIR_LOAD = 207,
    REPAIR_IMAGES = 208,
    REPAIR_BROWSE = 209,
    FULL_PAYLOAD = 210,
    SFC_CHAIN = 212,
    SFC_VERIFY = 213,
    SFC_REPAIR = 214,
    WORKFLOW = 216,
    MODE_BOTH = 217,
    MODE_SFC = 218,
    PROGRESS_TEXT = 714,
    NAV_WIM = 701,
    NAV_REPAIR = 702,
    PART_BOOT = 405,
    BOOT_TOOL = 406,
    BOOT_TOOL_BROWSE = 407,
    LOG_READABLE = 715,
    LOG_EXPAND = 716,
    LOG_TREE = 717,
    LOG_DETAIL = 718,
    LOG_SUMMARY = 719,
    LOG_SOURCE_SUMMARY = 720,
    LOG_BRIEF = 710,
    LOG_FULL = 711,
    LOG_COPY = 712,
    LOG_OPEN = 713,
    LOG = 301,
    PROGRESS = 302,
    STATUS = 303
};
struct Notice {
    int percent;
    std::wstring text;
};
struct Finished {
    int kind = 0;
    HRESULT hr = E_FAIL;
    std::wstring detail;
    std::vector<servicing::WimImage> images;
};
HWND window, tab, logEdit, progress, status;
HFONT font, heading, smallFont, monoFont;
HBRUSH bgBrush, surfaceBrush, navBrush, logBrush;
int flowSelection = 0;
bool fullLog = false, readableLog = false, expandedLog = false;
HWND logTree, logDetail;
std::map<int, workbench::PartitionChoice> selectedPartitions;
workbench::PartitionAccess partitionAccess;
std::array<HTREEITEM, 9> groupNodes{};
std::vector<workbench::LogGroup> displayedGroups;
uint64_t treeRefreshAt = 0;
uint64_t shownRevision = 0;
int sourceChoice = 0;
bool sfcSourceMode = false, sourceOnlineMode = true;
std::vector<RECT> cards;
HINSTANCE instance;
std::vector<HWND> wimControls, cbsControls;
std::vector<servicing::WimImage> images;
std::atomic_bool cancelled{false};
std::atomic<int> activePhase{0}; // 1: cooperative CBS/WIM; 2: SFC waits for natural exit.
bool busy = false, preview = false, partitionCleanupPending = false;
int selectedTab = 0;
std::wstring catalogPath;
std::wstring sessionLog, renderedLog;
std::vector<servicing::WimImage> repairImages;
std::wstring repairCatalogPath;

std::wstring Text(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(n + 1, L'\0');
    GetWindowTextW(h, s.data(), n + 1);
    s.resize(n);
    return s;
}
std::wstring Text(int id) {
    return Text(GetDlgItem(window, id));
}
std::wstring Hex(HRESULT hr) {
    wchar_t b[24];
    swprintf(b, 24, L"0x%08X", static_cast<unsigned>(hr));
    return b;
}
std::string Utf8(const std::wstring &s) {
    if (s.empty())
        return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0, nullptr, nullptr);
    std::string r(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), r.data(), n, nullptr, nullptr);
    return r;
}
std::wstring Wide(const std::string &s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring r(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), r.data(), n);
    return r;
}
std::wstring Escape(std::wstring s) {
    std::wstring r;
    for (auto c : s) {
        if (c == L'\n')
            r += L"\\n";
        else if (c == L'\r')
            r += L"\\r";
        else if (c == L'\t')
            r += L"\\t";
        else if (c == L'\\')
            r += L"\\\\";
        else
            r += c;
    }
    return r;
}
std::wstring Unescape(const std::wstring &s) {
    std::wstring r;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == L'\\' && i + 1 < s.size()) {
            auto c = s[++i];
            r += c == L'n' ? L'\n' : c == L'r' ? L'\r' : c == L't' ? L'\t' : c;
        } else
            r += s[i];
    }
    return r;
}
std::vector<std::wstring> Split(const std::wstring &s) {
    std::vector<std::wstring> r;
    size_t a = 0, b;
    while ((b = s.find(L'\t', a)) != s.npos) {
        r.push_back(s.substr(a, b - a));
        a = b + 1;
    }
    r.push_back(s.substr(a));
    return r;
}
std::wstring Quote(const std::wstring &s) {
    std::wstring r = L"\"";
    size_t slashes = 0;
    for (auto c : s) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'\"') {
            r.append(slashes * 2 + 1, L'\\');
            r += c;
        } else {
            r.append(slashes, L'\\');
            r += c;
        }
        slashes = 0;
    }
    r.append(slashes * 2, L'\\');
    return r + L"\"";
}

void Append(const std::wstring &s) {
    workbench::Log(s, true);
}
void Report(int p, const std::wstring &s) {
    bool detail = p >= 0 || (s.size() > 2 && s[1] == L':');
    workbench::Log(s, !detail, L"引擎", detail ? workbench::LogLevel::Detail : workbench::LogLevel::Info);
    static std::mutex mutex;
    static ULONGLONG last = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto now = GetTickCount64();
        if (detail && now - last < 250)
            return;
        if (detail)
            last = now;
    }
    auto n = new Notice{p, s};
    if (!PostMessageW(window, WM_PROGRESS, 0, LPARAM(n)))
        delete n;
}
int Flow() {
    return flowSelection;
}
bool UsesCbs() {
    return Flow() != 2;
}
bool UsesSfc() {
    return Flow() != 0;
}
void Layout();
void RefreshEnabled();
HTREEITEM TreeRow(HTREEITEM parent, const std::wstring &text, LPARAM data = 0) {
    TVINSERTSTRUCTW item{};
    item.hParent = parent;
    item.hInsertAfter = TVI_LAST;
    item.item.mask = TVIF_TEXT | TVIF_PARAM;
    item.item.pszText = const_cast<wchar_t *>(text.c_str());
    item.item.lParam = data;
    return TreeView_InsertItem(logTree, &item);
}
std::wstring TreeLabel(std::wstring text) {
    for (auto &c : text)
        if (c == L'\r' || c == L'\n' || c == L'\t')
            c = L' ';
    if (text.size() > 320)
        text = text.substr(0, 320) + L" …";
    return text;
}
void FillGroup(size_t i) {
    auto node = groupNodes[i];
    while (auto child = TreeView_GetChild(logTree, node))
        TreeView_DeleteItem(logTree, child);
    auto &g = displayedGroups[i];
    if (g.clipped)
        TreeRow(node, L"早期分组记录已移出显示缓冲");
    for (size_t j = 0; j < g.rows.size(); ++j)
        TreeRow(node, TreeLabel(g.rows[j]), LPARAM(1 + (i << 20) + j));
    if (g.rows.empty())
        TreeRow(node, L"尚无记录");
}
void RenderStructured() {
    auto oldGroups = std::move(displayedGroups);
    displayedGroups = workbench::StructuredLog();
    uint64_t total = 0;
    for (const auto &g : displayedGroups)
        total += g.total;
    std::wstring detected, repaired;
    for (auto it = displayedGroups[3].rows.rbegin(); it != displayedGroups[3].rows.rend(); ++it) {
        if (it->find(L"Summary:") != it->npos)
            break;
        auto number = [&](const wchar_t *key) {
            auto at = it->find(key);
            if (at == it->npos)
                return std::wstring();
            at += wcslen(key);
            while (at < it->size() && iswspace((*it)[at]))
                ++at;
            auto end = at;
            while (end < it->size() && (*it)[end] >= L'0' && (*it)[end] <= L'9')
                ++end;
            return it->substr(at, end - at);
        };
        if (detected.empty())
            detected = number(L"Total Detected Corruption:");
        if (repaired.empty())
            repaired = number(L"Total Repaired Corruption:");
        if (!detected.empty() && !repaired.empty())
            break;
    }
    auto summary = L"日志记录：" + std::to_wstring(total) + L"  /  取源 " +
                   std::to_wstring(displayedGroups[2].total) + L"  /  警告与错误 " +
                   std::to_wstring(displayedGroups[4].total);
    if (!detected.empty() || !repaired.empty())
        summary += L"    CBS 日志最近汇总：检测 " + (detected.empty() ? L"待定" : detected) + L" / 修复 " +
                   (repaired.empty() ? L"待定" : repaired);
    SetDlgItemTextW(window, LOG_SUMMARY, summary.c_str());
    std::wstring source = L"来源：尚无本次请求记录";
    for (auto it = displayedGroups[1].rows.rbegin(); it != displayedGroups[1].rows.rend(); ++it)
        if (it->find(L"[配置]") != it->npos) {
            auto start = it->find(L"[配置]");
            source = L"请求配置：" + it->substr(start + 5);
            break;
        }
    SetDlgItemTextW(window, LOG_SOURCE_SUMMARY, TreeLabel(source).c_str());
    SendMessageW(logTree, WM_SETREDRAW, FALSE, 0);
    for (size_t i = 0; i < displayedGroups.size(); ++i) {
        auto &g = displayedGroups[i];
        auto title =
            g.title + L"  ·  " + std::to_wstring(g.total) + L" 条" + (g.clipped ? L"（显示最近记录）" : L"");
        if (!groupNodes[i]) {
            groupNodes[i] = TreeRow(TVI_ROOT, title, -LPARAM(i + 1));
            TreeRow(groupNodes[i], L"展开查看记录");
        } else {
            TVITEMW item{};
            item.mask = TVIF_TEXT;
            item.hItem = groupNodes[i];
            item.pszText = title.data();
            TreeView_SetItem(logTree, &item);
        }
        if (TreeView_GetItemState(logTree, groupNodes[i], TVIS_EXPANDED) & TVIS_EXPANDED) {
            bool append = i < oldGroups.size() && !oldGroups[i].rows.empty() &&
                          g.rows.size() >= oldGroups[i].rows.size() &&
                          g.rows.front() == oldGroups[i].rows.front();
            if (append) {
                for (size_t j = oldGroups[i].rows.size(); j < g.rows.size(); ++j)
                    TreeRow(groupNodes[i], TreeLabel(g.rows[j]), LPARAM(1 + (i << 20) + j));
            } else if (i >= oldGroups.size() || g.rows != oldGroups[i].rows)
                FillGroup(i);
        }
    }
    SendMessageW(logTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(logTree, nullptr, FALSE);
}
void RenderLog(bool force = false) {
    auto rev = workbench::LogRevision();
    if (!force && rev == shownRevision)
        return;
    if (readableLog) {
        auto now = GetTickCount64();
        if (!force && now - treeRefreshAt < 1000)
            return;
        treeRefreshAt = now;
        shownRevision = rev;
        RenderStructured();
        return;
    }
    shownRevision = rev;
    auto text = workbench::LogText(fullLog);
    if (!force && text == renderedLog)
        return;
    SCROLLINFO scroll{};
    scroll.cbSize = sizeof(scroll);
    scroll.fMask = SIF_ALL;
    GetScrollInfo(logEdit, SB_VERT, &scroll);
    bool follow = force || scroll.nPos + int(scroll.nPage) >= scroll.nMax - 1;
    int first = int(SendMessageW(logEdit, EM_GETFIRSTVISIBLELINE, 0, 0));
    DWORD a = 0, b = 0;
    SendMessageW(logEdit, EM_GETSEL, WPARAM(&a), LPARAM(&b));
    SetWindowTextW(logEdit, text.c_str());
    if (follow) {
        SendMessageW(logEdit, EM_SETSEL, text.size(), text.size());
        SendMessageW(logEdit, EM_SCROLLCARET, 0, 0);
    } else {
        SendMessageW(logEdit, EM_SETSEL, a, b);
        SendMessageW(logEdit, EM_LINESCROLL, 0, first);
    }
    renderedLog = std::move(text);
}
void CopyLog() {
    auto text = readableLog ? workbench::StructuredLogText() : workbench::LogText(fullLog);
    if (!OpenClipboard(window))
        return;
    EmptyClipboard();
    auto h = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
    if (h) {
        auto p = GlobalLock(h);
        if (p) {
            memcpy(p, text.c_str(), (text.size() + 1) * sizeof(wchar_t));
            GlobalUnlock(h);
            if (!SetClipboardData(CF_UNICODETEXT, h))
                GlobalFree(h);
        } else
            GlobalFree(h);
    }
    CloseClipboard();
}
bool Checked(int id) {
    return SendDlgItemMessageW(window, id, BM_GETCHECK, 0, 0) == BST_CHECKED;
}
HWND Control(const wchar_t *cls, const wchar_t *title, DWORD style, int id, int page) {
    bool push = !lstrcmpiW(cls, L"BUTTON") && (style & BS_TYPEMASK) == BS_PUSHBUTTON;
    if (push)
        style = (style & ~BS_TYPEMASK) | BS_OWNERDRAW;
    if (!lstrcmpiW(cls, L"EDIT"))
        style &= ~WS_BORDER;
    HWND h = CreateWindowExW(0, cls, title, WS_CHILD | WS_VISIBLE | style, 0, 0, 200, 200, window,
                             HMENU(INT_PTR(id)), instance, nullptr);
    if (lstrcmpiW(cls, L"COMBOBOX") == 0)
        SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SendMessageW(h, WM_SETFONT, WPARAM(font), TRUE);
    SetWindowTheme(h, L"Explorer", nullptr);
    if (page == 0)
        wimControls.push_back(h);
    else if (page == 1)
        cbsControls.push_back(h);
    return h;
}
double layoutScale = 1;
int Y(int y) {
    return int(y * layoutScale);
}
void Place(int id, int x, int y, int w, int h) {
    bool fixed = id == 501 || id == NAV_WIM || id == NAV_REPAIR;
    MoveWindow(GetDlgItem(window, id), x, fixed ? y : Y(y), w, fixed ? h : std::max(24, Y(h)), TRUE);
}

void SourceChoices() {
    bool onlySfc = !UsesCbs(), online = Checked(ONLINE);
    if (onlySfc == sfcSourceMode && online == sourceOnlineMode)
        return;
    if (!sfcSourceMode)
        sourceChoice = int(SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0));
    bool droppedWu = !onlySfc && !online && sourceChoice == 3;
    if (droppedWu) {
        sourceChoice = 0;
        Append(L"离线目标不能使用 Windows Update，已切换为自动；可选择匹配的本地来源。");
    }
    SendDlgItemMessageW(window, SOURCE_KIND, CB_RESETCONTENT, 0, 0);
    if (onlySfc)
        SendDlgItemMessageW(window, SOURCE_KIND, CB_ADDSTRING, 0, LPARAM(L"目标组件存储"));
    else {
        for (auto text : {L"自动", L"Windows 目录", L"WIM 映像"})
            SendDlgItemMessageW(window, SOURCE_KIND, CB_ADDSTRING, 0, LPARAM(text));
        if (online)
            SendDlgItemMessageW(window, SOURCE_KIND, CB_ADDSTRING, 0, LPARAM(L"Windows Update"));
    }
    SendDlgItemMessageW(window, SOURCE_KIND, CB_SETCURSEL,
                        onlySfc ? 0 : std::clamp(sourceChoice, 0, online ? 3 : 2), 0);
    sfcSourceMode = onlySfc;
    sourceOnlineMode = online;
}

void ShowPage(int n) {
    selectedTab = n;
    SetWindowTextW(GetDlgItem(window, 501), n == 0 ? L"镜像释放" : L"系统修复");
    RefreshEnabled();
    Layout();
    InvalidateRect(window, nullptr, TRUE);
}
void RefreshEnabled() {
    if (!GetDlgItem(window, WORKFLOW))
        return;
    SourceChoices();
    for (int id : std::vector<int>{SOURCE,      LOAD,          IMAGES,        DEST,         BOOT,
                                   WTG,         BOOTPART,      FIRMWARE,      APPLY,        ONLINE,
                                   ROOT,        SCAN,          RESTORE,       SOURCE_KIND,  REPAIR_PATH,
                                   REPAIR_LOAD, REPAIR_IMAGES, REPAIR_BROWSE, FULL_PAYLOAD, WORKFLOW,
                                   MODE_BOTH,   MODE_SFC,      PART_BOOT,     BOOT_TOOL,    BOOT_TOOL_BROWSE,
                                   401,         402,           404,           NAV_WIM,      NAV_REPAIR})
        EnableWindow(GetDlgItem(window, id), !busy);
    EnableWindow(GetDlgItem(window, CANCEL), busy && !cancelled);
    EnableWindow(GetDlgItem(window, SOURCE_KIND), !busy && UsesCbs());
    bool wu =
        UsesCbs() && Checked(ONLINE) && SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0) == 3;
    if (wu) {
        SendDlgItemMessageW(window, FULL_PAYLOAD, BM_SETCHECK, BST_CHECKED, 0);
    }
    EnableWindow(GetDlgItem(window, FULL_PAYLOAD), !busy && !wu);
    int i = int(SendDlgItemMessageW(window, IMAGES, CB_GETCURSEL, 0, 0));
    bool portable = i >= 0 && size_t(i) < images.size() &&
                    (images[i].major > 6 || (images[i].major == 6 && images[i].minor >= 2));
    EnableWindow(GetDlgItem(window, WTG), !busy && portable);
    if (!portable)
        SendDlgItemMessageW(window, WTG, BM_SETCHECK, BST_UNCHECKED, 0);
    SetDlgItemTextW(window, SCAN, UsesCbs() ? L"验证受损" : L"验证系统文件");
    SetDlgItemTextW(window, RESTORE, UsesCbs() ? L"修复受损" : L"修复系统文件");
    SetDlgItemTextW(window, CANCEL, activePhase == 2 ? L"本阶段后停止" : L"停止");
    if (preview)
        for (int id : std::vector<int>{LOAD, REPAIR_LOAD, APPLY, SCAN, RESTORE})
            EnableWindow(GetDlgItem(window, id), FALSE);
}
void DisplayProgress(int value) {
    bool known = value >= 0;
    SendMessageW(progress, PBM_SETMARQUEE, FALSE, 0);
    auto style = GetWindowLongPtrW(progress, GWL_STYLE);
    SetWindowLongPtrW(progress, GWL_STYLE, known ? style & ~PBS_MARQUEE : style | PBS_MARQUEE);
    if (known) {
        value = std::clamp(value, 0, 100);
        SendMessageW(progress, PBM_SETPOS, value, 0);
        auto label = std::to_wstring(value) + L"%";
        SetDlgItemTextW(window, PROGRESS_TEXT, label.c_str());
    } else {
        SendMessageW(progress, PBM_SETMARQUEE, TRUE, 35);
        SetDlgItemTextW(window, PROGRESS_TEXT, L"进行中");
    }
}
void SetBusy(bool v) {
    busy = v;
    if (!v) {
        partitionAccess.Clear();
        partitionCleanupPending = partitionAccess.Pending();
        activePhase = 0;
        SendMessageW(progress, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(progress, GWL_STYLE, GetWindowLongPtrW(progress, GWL_STYLE) & ~PBS_MARQUEE);
    }
    if (v) {
        cancelled = false;
        activePhase = 1;
        SendMessageW(progress, PBM_SETPOS, 0, 0);
        DisplayProgress(-1);
    }
    RefreshEnabled();
}
void BrowseFile(int id = SOURCE) {
    wchar_t b[32768] = {};
    OPENFILENAMEW o = {};
    o.lStructSize = sizeof(o);
    o.hwndOwner = window;
    o.lpstrFilter = id == BOOT_TOOL ? L"Windows 引导工具 (bootsect.exe)\0bootsect.exe\0所有程序\0*.exe\0"
                                    : L"Windows 映像 (*.wim)\0*.wim\0所有文件\0*.*\0";
    o.lpstrFile = b;
    o.nMaxFile = 32768;
    o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&o)) {
        SetDlgItemTextW(window, id, b);
        if (id == SOURCE) {
            images.clear();
            catalogPath.clear();
            SendDlgItemMessageW(window, IMAGES, CB_RESETCONTENT, 0, 0);
        } else if (id == REPAIR_PATH) {
            repairImages.clear();
            repairCatalogPath.clear();
            SendDlgItemMessageW(window, REPAIR_IMAGES, CB_RESETCONTENT, 0, 0);
        }
        RefreshEnabled();
    }
}
void BrowseFolder(int id) {
    selectedPartitions.erase(id);
    BROWSEINFOW b = {};
    b.hwndOwner = window;
    b.lpszTitle = id == DEST          ? L"选择镜像释放目标"
                  : id == REPAIR_PATH ? L"选择独立健康来源的 Windows 目录或挂载根目录"
                                      : L"选择离线 Windows 所在根目录";
    b.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE p = SHBrowseForFolderW(&b);
    if (p) {
        wchar_t s[MAX_PATH];
        if (SHGetPathFromIDListW(p, s))
            SetDlgItemTextW(window, id, s);
        CoTaskMemFree(p);
    }
}

void ChoosePartition(int id) {
    if (busy)
        return;
    workbench::PartitionChoice choice;
    if (workbench::PickPartition(window, choice)) {
        selectedPartitions[id] = choice;
        SetDlgItemTextW(window, id, choice.Caption().c_str());
        Layout();
    }
}
bool ResolvePartition(int id, std::wstring &path) {
    auto it = selectedPartitions.find(id);
    if (it == selectedPartitions.end() || Text(id) != it->second.Caption())
        return true;
    std::wstring error;
    if (partitionAccess.Resolve(it->second, path, error))
        return true;
    partitionAccess.Clear();
    MessageBoxW(window, error.c_str(), L"分区访问失败", MB_ICONERROR);
    return false;
}

servicing::CbsResult IsolatedCbs(const servicing::CbsOptions &o) {
    servicing::CbsResult result;
    result.stage = L"启动 CBS 宿主";
    if (cancelled) {
        result.hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        result.cancelRequested = true;
        result.detail = L"已停止，未启动 CBS 宿主。";
        return result;
    }
    wchar_t winDir[32768]{};
    GetWindowsDirectoryW(winDir, 32768);
    std::wstring engineLog =
        std::wstring(winDir) + (o.online ? L"\\Logs\\CBS\\CBS.log" : L"\\Logs\\CBS\\OfflineCbs.log");
    workbench::FileLogFollower nativeLog(engineLog, workbench::FileLogOffset(engineLog), L"CBS");
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE read = nullptr, write = nullptr, event = nullptr;
    if (!CreatePipe(&read, &write, &sa, 0)) {
        result.hr = HRESULT_FROM_WIN32(GetLastError());
        return result;
    }
    SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
    event = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!event) {
        result.hr = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(read);
        CloseHandle(write);
        return result;
    }
    wchar_t executable[32768]{};
    DWORD executableLength = GetModuleFileNameW(nullptr, executable, 32768);
    if (!executableLength || executableLength >= 32768) {
        result.hr = E_FAIL;
        CloseHandle(read);
        CloseHandle(write);
        CloseHandle(event);
        return result;
    }
    auto handleString = [](HANDLE h) { return std::to_wstring(reinterpret_cast<uintptr_t>(h)); };
    std::wstring command = Quote(executable) + L" --cbs-worker --pipe " + handleString(write) +
                           L" --cancel-handle " + handleString(event) +
                           (o.online ? L" --online" : L" --offline " + Quote(o.root)) +
                           (o.operation == servicing::CbsOperation::Scan ? L" --scan" : L" --restore");
    if (o.sourceKind == servicing::RepairSourceKind::Directory)
        command += L" --source-directory " + Quote(o.source);
    else if (o.sourceKind == servicing::RepairSourceKind::Wim)
        command += L" --source-wim " + Quote(o.source) + L" --source-index " + std::to_wstring(o.sourceIndex);
    if (o.sourceKind == servicing::RepairSourceKind::WindowsUpdate)
        command += L" --windows-update";
    else if (o.sourceKind == servicing::RepairSourceKind::LocalOnly)
        command += L" --local-only";
    command += o.fullPayloadCheck ? L" --full-payload" : L" --automatic-compat";
    workbench::Log(command, false, L"CBS 命令", workbench::LogLevel::Detail);
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> memory(bytes);
    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(memory.data());
    bool listReady = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytes) != FALSE;
    HANDLE handles[] = {write, event};
    bool attrs =
        listReady && UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                               handles, sizeof(handles), nullptr, nullptr);
    if (cancelled)
        SetEvent(event);
    PROCESS_INFORMATION pi = {};
    BOOL ok = attrs && CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
                                      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
                                      &si.StartupInfo, &pi);
    DWORD error = GetLastError();
    if (listReady)
        DeleteProcThreadAttributeList(si.lpAttributeList);
    CloseHandle(write);
    if (!ok) {
        CloseHandle(read);
        CloseHandle(event);
        result.hr = HRESULT_FROM_WIN32(error);
        result.detail = L"无法启动隔离宿主。";
        return result;
    }
    workbench::Log(L"PID=" + std::to_wstring(pi.dwProcessId), false, L"CBS 宿主",
                   workbench::LogLevel::Detail);
    CloseHandle(pi.hThread);
    struct ChildOwner {
        HANDLE &process;
        HANDLE &output;
        HANDLE &stop;
        ~ChildOwner() {
            if (output) {
                CloseHandle(output);
                output = nullptr;
            }
            if (process) {
                WaitForSingleObject(process, INFINITE);
                CloseHandle(process);
                process = nullptr;
            }
            if (stop) {
                CloseHandle(stop);
                stop = nullptr;
            }
        }
    } owner{pi.hProcess, read, event};
    std::atomic_bool finished{false};
    std::thread watcher([&] {
        while (!finished) {
            if (cancelled)
                SetEvent(event);
            Sleep(50);
        }
    });
    struct WatchOwner {
        std::atomic_bool &done;
        std::thread &thread;
        ~WatchOwner() {
            done = true;
            if (thread.joinable())
                thread.join();
        }
    } watch{finished, watcher};
    std::string pending;
    char buffer[4096];
    DWORD count;
    bool gotResult = false, invalidProtocol = false;
    while (ReadFile(read, buffer, sizeof(buffer), &count, nullptr) && count) {
        pending.append(buffer, count);
        size_t end;
        while ((end = pending.find('\n')) != pending.npos) {
            auto fields = Split(Wide(pending.substr(0, end)));
            pending.erase(0, end + 1);
            if (fields.size() >= 3 && fields[0] == L"P") {
                try {
                    Report(std::stoi(fields[1]), Unescape(fields[2]));
                } catch (...) {
                }
            }
            if (!fields.empty() && fields[0] == L"R") {
                try {
                    if (fields.size() != 10 || gotResult)
                        throw 1;
                    result.hr = HRESULT(std::stoul(fields[1], nullptr, 16));
                    result.health = std::stoi(fields[2]);
                    result.cancelRequested = fields[3] == L"1";
                    result.imageStateUnknown = fields[4] == L"1";
                    result.stage = Unescape(fields[5]);
                    result.detail = Unescape(fields[6]);
                    result.cbsLog = Unescape(fields[7]);
                    if (fields.size() >= 10) {
                        result.requiredAction = std::stoul(fields[8]);
                        result.requiredActionAvailable = fields[9] == L"1";
                    }
                    gotResult = true;
                } catch (...) {
                    invalidProtocol = true;
                }
            }
        }
        if (pending.size() > 1024 * 1024) {
            invalidProtocol = true;
            pending.clear();
            Report(-1, L"宿主输出超过限制，已丢弃非协议内容。");
        }
    }
    CloseHandle(read);
    read = nullptr;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exit))
        exit = ERROR_GEN_FAILURE;
    CloseHandle(pi.hProcess);
    pi.hProcess = nullptr;
    finished = true;
    watcher.join();
    CloseHandle(event);
    event = nullptr;
    if (gotResult && result.hr == S_OK && exit != 0) {
        result.hr = HRESULT_FROM_WIN32(exit);
        result.health = -1;
        result.stage = L"CBS 宿主退出状态";
        result.detail = L"宿主返回成功结果后异常退出，不能认定维护已完成。退出状态：" + Hex(HRESULT(exit));
        result.imageStateUnknown = true;
    }
    if (!gotResult || invalidProtocol || !pending.empty()) {
        result.hr = exit ? HRESULT_FROM_WIN32(exit) : E_FAIL;
        result.detail = L"CBS 宿主未返回完整结果；不能认定操作完成。";
        result.imageStateUnknown = true;
    }
    workbench::Log(
        L"HRESULT=" + Hex(result.hr) + L"; health=" + std::to_wstring(result.health) + L"; requiredAction=" +
            (result.requiredActionAvailable ? std::to_wstring(result.requiredAction) : L"unknown") +
            L"; imageStateUnknown=" + std::to_wstring(result.imageStateUnknown) + L"; workerExit=" +
            std::to_wstring(exit) + L"; " + result.stage + L"; " + result.detail,
        false, L"CBS 结果", workbench::LogLevel::Detail);
    return result;
}

void SetPhase(int phase) {
    activePhase = phase;
    PostMessageW(window, WM_PHASE, 0, 0);
}
servicing::SfcResult IsolatedSfc(const servicing::SfcOptions &o) {
    servicing::SfcResult result;
    result.stage = L"启动 SFC 宿主";
    if (cancelled) {
        result.hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        result.stopRequested = true;
        result.detail = L"已停止，未启动 SFC 宿主。";
        return result;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE read = nullptr, write = nullptr, event = nullptr;
    if (!CreatePipe(&read, &write, &sa, 0)) {
        result.hr = HRESULT_FROM_WIN32(GetLastError());
        return result;
    }
    SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
    event = CreateEventW(&sa, TRUE, cancelled ? TRUE : FALSE, nullptr);
    if (!event) {
        result.hr = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(read);
        CloseHandle(write);
        return result;
    }
    wchar_t executable[32768];
    DWORD length = GetModuleFileNameW(nullptr, executable, 32768);
    if (!length || length >= 32768) {
        result.hr = E_FAIL;
        CloseHandle(read);
        CloseHandle(write);
        CloseHandle(event);
        return result;
    }
    auto handleString = [](HANDLE h) { return std::to_wstring(reinterpret_cast<uintptr_t>(h)); };
    std::wstring command = Quote(executable) + L" --sfc-worker --pipe " + handleString(write) +
                           L" --cancel-handle " + handleString(event) +
                           (o.online ? L" --online" : L" --offline " + Quote(o.root)) +
                           (o.operation == servicing::SfcOperation::Repair ? L" --repair" : L" --verify");
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> memory(bytes);
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(memory.data());
    bool ready = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytes) != FALSE;
    HANDLE inherited[]{write, event};
    bool attrs = ready && UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                    inherited, sizeof(inherited), nullptr, nullptr);
    if (cancelled)
        SetEvent(event);
    PROCESS_INFORMATION pi{};
    BOOL ok = attrs && CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
                                      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr,
                                      &si.StartupInfo, &pi);
    DWORD error = GetLastError();
    if (ready)
        DeleteProcThreadAttributeList(si.lpAttributeList);
    CloseHandle(write);
    if (!ok) {
        result.hr = HRESULT_FROM_WIN32(error);
        CloseHandle(read);
        CloseHandle(event);
        return result;
    }
    CloseHandle(pi.hThread);
    struct ChildOwner {
        HANDLE &process;
        HANDLE &output;
        HANDLE &stop;
        ~ChildOwner() {
            if (output) {
                CloseHandle(output);
                output = nullptr;
            }
            if (process) {
                WaitForSingleObject(process, INFINITE);
                CloseHandle(process);
                process = nullptr;
            }
            if (stop) {
                CloseHandle(stop);
                stop = nullptr;
            }
        }
    } owner{pi.hProcess, read, event};
    std::atomic_bool finished{false};
    std::thread watcher([&] {
        while (!finished) {
            if (cancelled)
                SetEvent(event);
            Sleep(50);
        }
    });
    struct WatchOwner {
        std::atomic_bool &done;
        std::thread &thread;
        ~WatchOwner() {
            done = true;
            if (thread.joinable())
                thread.join();
        }
    } watch{finished, watcher};
    std::unique_ptr<workbench::FileLogFollower> nativeLog;
    workbench::Log(command + L"; PID=" + std::to_wstring(pi.dwProcessId), false, L"SFC 命令",
                   workbench::LogLevel::Detail);
    std::string pending;
    char buffer[4096];
    DWORD count = 0;
    bool gotResult = false, invalidProtocol = false;
    while (ReadFile(read, buffer, sizeof(buffer), &count, nullptr) && count) {
        pending.append(buffer, count);
        size_t end;
        while ((end = pending.find('\n')) != pending.npos) {
            auto fields = Split(Wide(pending.substr(0, end)));
            pending.erase(0, end + 1);
            if (fields.size() >= 3 && fields[0] == L"P") {
                try {
                    Report(std::stoi(fields[1]), Unescape(fields[2]));
                } catch (...) {
                }
            }
            if (fields.size() == 2 && fields[0] == L"L" && !nativeLog)
                nativeLog.reset(new workbench::FileLogFollower(Unescape(fields[1]), 0, L"SFC"));
            if (fields.size() == 13 && fields[0] == L"S") {
                try {
                    if (gotResult)
                        throw 1;
                    int report = std::stoi(fields[6]);
                    if (report < 0 || report > 4)
                        throw 1;
                    result.hr = HRESULT(std::stoul(fields[1], nullptr, 16));
                    result.exitCode = std::stoul(fields[2]);
                    result.started = fields[3] == L"1";
                    result.processExited = fields[4] == L"1";
                    result.stopRequested = fields[5] == L"1";
                    result.report = static_cast<servicing::SfcReport>(report);
                    result.stage = Unescape(fields[7]);
                    result.detail = Unescape(fields[8]);
                    result.rawLog = Unescape(fields[9]);
                    result.textLog = Unescape(fields[10]);
                    result.offLog = Unescape(fields[11]);
                    if (fields[12] != L"end")
                        throw 1;
                    gotResult = true;
                } catch (...) {
                    invalidProtocol = true;
                }
            }
        }
        if (pending.size() > 1024 * 1024) {
            pending.clear();
            invalidProtocol = true;
        }
    }
    CloseHandle(read);
    read = nullptr;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit = 1;
    GetExitCodeProcess(pi.hProcess, &exit);
    CloseHandle(pi.hProcess);
    pi.hProcess = nullptr;
    finished = true;
    watcher.join();
    CloseHandle(event);
    event = nullptr;
    bool successConsistent =
        result.started && result.processExited && result.exitCode == 0 &&
        (result.report == servicing::SfcReport::Clean || result.report == servicing::SfcReport::Repaired);
    if (!gotResult || invalidProtocol || (result.hr == S_OK && (exit != 0 || !successConsistent))) {
        result.hr = E_FAIL;
        result.report = servicing::SfcReport::Unknown;
        result.stage = L"SFC 宿主结果未确认";
        result.detail =
            L"结果协议不完整或宿主异常退出，不能确认系统文件状态。宿主退出码：" + std::to_wstring(exit);
    }
    return result;
}
std::wstring SfcDetails(const servicing::SfcResult &r) {
    auto text = r.stage + L"：" + r.detail + L"\r\nSFC 报告：" + servicing::SfcReportText(r.report);
    if (r.processExited)
        text += L"\r\n系统工具退出码：" + std::to_wstring(r.exitCode) + L"（退出码不能单独证明完整性）";
    if (!r.rawLog.empty())
        text += L"\r\n原始输出：" + r.rawLog;
    if (!r.textLog.empty())
        text += L"\r\n解码输出：" + r.textLog;
    if (!r.offLog.empty())
        text += L"\r\nSFC 日志：" + r.offLog;
    return text;
}
void RunSfcStages(const servicing::SfcOptions &o, Finished &done) {
    if (cancelled) {
        done.hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        done.detail += L"\r\n已停止，未启动 SFC 后续阶段。";
        return;
    }
    SetPhase(2);
    Report(-1, o.operation == servicing::SfcOperation::Repair ? L"SFC 修复阶段：等待系统工具自然结束。"
                                                              : L"SFC 验证阶段：等待系统工具自然结束。");
    auto r = IsolatedSfc(o);
    done.hr = r.hr;
    done.detail += L"\r\n【系统文件】" + SfcDetails(r);
    if (o.operation == servicing::SfcOperation::Repair && r.hr == S_OK) {
        if (cancelled || r.stopRequested) {
            done.hr = S_FALSE;
            done.detail += L"\r\n当前 SFC 阶段已结束，按请求停止；未执行后续完整复验。";
            return;
        }
        auto verify = o;
        verify.operation = servicing::SfcOperation::Verify;
        Report(-1, L"SFC 修复阶段已结束，开始完整复验。");
        if (cancelled) {
            done.hr = S_FALSE;
            done.detail += L"\r\n已停止，未启动 SFC 完整复验。";
            return;
        }
        auto v = IsolatedSfc(verify);
        done.hr = v.hr;
        done.detail += L"\r\n【SFC 完整复验】" + SfcDetails(v);
        if (v.hr == S_OK && v.report != servicing::SfcReport::Clean) {
            done.hr = S_FALSE;
            done.detail += L"\r\n复验未得到明确无违规结果。";
        }
    }
    if (cancelled || r.stopRequested)
        done.detail += L"\r\n停止请求已记录，系统工具已自然结束。";
}

void Launch(int kind) {
    if (busy || preview)
        return;
    if (kind == 1 || kind == 5) {
        auto path = Text(kind == 1 ? SOURCE : REPAIR_PATH);
        if (path.empty()) {
            MessageBoxW(window, L"请先选择 WIM 文件。", L"释放映像", MB_ICONINFORMATION);
            return;
        }
        SetBusy(true);
        std::thread([path, kind] {
            auto done = new Finished;
            done->kind = kind;
            try {
                servicing::WimResult r;
                done->images = servicing::EnumerateWim(path, r);
                done->hr = r.hr;
                done->detail = SUCCEEDED(r.hr) ? path : r.stage + L"：" + r.detail;
            } catch (const std::exception &e) {
                done->hr = E_FAIL;
                done->detail = Wide(e.what());
            } catch (...) {
                done->hr = E_FAIL;
                done->detail = L"读取映像失败。";
            }
            PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
        }).detach();
        return;
    }
    if (kind == 2) {
        int choice = int(SendDlgItemMessageW(window, IMAGES, CB_GETCURSEL, 0, 0));
        if (choice < 0 || size_t(choice) >= images.size() || catalogPath != Text(SOURCE)) {
            MessageBoxW(window, L"请读取当前 WIM 文件并选择其中的映像。", L"释放映像", MB_ICONINFORMATION);
            return;
        }
        servicing::WimOptions o;
        o.source = Text(SOURCE);
        o.destination = Text(DEST);
        o.imageIndex = images[choice].index;
        o.addBoot = Checked(BOOT);
        o.windowsToGo = Checked(WTG);
        o.bootPartition = Text(BOOTPART);
        o.bootCodeTool = Text(BOOT_TOOL);
        o.firmware = int(SendDlgItemMessageW(window, FIRMWARE, CB_GETCURSEL, 0, 0));
        std::wstring confirmation = L"即将向以下位置释放镜像：\n" + o.destination + L"\n\n镜像：" +
                                    std::to_wstring(o.imageIndex) + L" — " + images[choice].name +
                                    (o.windowsToGo ? L"\nWindowsToGo：启用" : L"") +
                                    (o.addBoot ? L"\n启动分区：" + o.bootPartition : L"") +
                                    L"\n\n只允许向独立磁盘上的空白分区释放。请确认已经备份数据；中途停止可能"
                                    L"留下不完整的系统。是否继续？";
        if (MessageBoxW(window, confirmation.c_str(), L"确认释放目标",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
            return;
        if (!ResolvePartition(DEST, o.destination) ||
            (o.addBoot && !ResolvePartition(BOOTPART, o.bootPartition)))
            return;
        SetBusy(true);
        Append(L"开始释放映像。");
        std::thread([o] {
            auto done = new Finished;
            done->kind = 2;
            try {
                auto r = servicing::ApplyWim(o, cancelled, Report);
                done->hr = r.hr;
                done->detail = r.stage + L"：" + r.detail;
                if (r.partialChanges)
                    done->detail += L"\r\n目标可能已发生部分修改，请检查日志和目标状态。";
            } catch (const std::exception &e) {
                done->hr = E_FAIL;
                done->detail = Wide(e.what());
            } catch (...) {
                done->hr = E_FAIL;
                done->detail = L"任务异常结束，目标状态需要检查。";
            }
            PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
        }).detach();
        return;
    }
    servicing::SfcOptions sfc;
    sfc.online = Checked(ONLINE);
    sfc.root = Text(ROOT);
    sfc.operation =
        (kind == 3 || kind == 6) ? servicing::SfcOperation::Verify : servicing::SfcOperation::Repair;
    if (sfc.online) {
        sfc.root.clear();
    }
    bool chain = (kind == 3 || kind == 4) && Flow() == 1;
    if (kind == 6 || kind == 7) {
        if (kind == 7 &&
            MessageBoxW(window,
                        L"将使用系统 SFC 检查并修复受保护系统文件，然后完整复验。SFC "
                        L"运行中不能强制取消，只能等待当前阶段结束。是否继续？",
                        L"SFC 修复系统文件", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
            return;
        if (!sfc.online && !ResolvePartition(ROOT, sfc.root))
            return;
        SetBusy(true);
        Append(kind == 6 ? L"开始 SFC 完整验证。" : L"开始 SFC 修复及复验。");
        std::thread([sfc, kind] {
            auto done = new Finished;
            done->kind = kind;
            try {
                RunSfcStages(sfc, *done);
            } catch (...) {
                done->hr = E_FAIL;
                done->detail = L"SFC 宿主通信异常，系统文件状态尚未确认。";
            }
            PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
        }).detach();
        return;
    }
    servicing::CbsOptions o;
    o.fullPayloadCheck = Checked(FULL_PAYLOAD);
    o.online = Checked(ONLINE);
    o.root = Text(ROOT);
    o.operation = kind == 3 ? servicing::CbsOperation::Scan : servicing::CbsOperation::Restore;
    if (kind == 4) {
        int sourceKind = int(SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0));
        if (sourceKind == 1) {
            o.sourceKind = servicing::RepairSourceKind::Directory;
            o.source = Text(REPAIR_PATH);
        } else if (sourceKind == 2) {
            int selected = int(SendDlgItemMessageW(window, REPAIR_IMAGES, CB_GETCURSEL, 0, 0));
            if (selected < 0 || size_t(selected) >= repairImages.size() ||
                repairCatalogPath != Text(REPAIR_PATH)) {
                MessageBoxW(window, L"请读取当前修复 WIM 并选择正确的映像版本。", L"修复来源",
                            MB_ICONINFORMATION);
                return;
            }
            o.sourceKind = servicing::RepairSourceKind::Wim;
            o.source = Text(REPAIR_PATH);
            o.sourceIndex = repairImages[selected].index;
        } else if (sourceKind == 3) {
            o.sourceKind = servicing::RepairSourceKind::WindowsUpdate;
            o.fullPayloadCheck = true;
        }
        if ((sourceKind == 1 || sourceKind == 2) && o.source.empty()) {
            MessageBoxW(window, L"请指定修复来源路径。", L"修复来源", MB_ICONINFORMATION);
            return;
        }
    }
    if (kind == 4) {
        auto text =
            L"将对" + std::wstring(o.online ? L"当前运行的 Windows" : L"离线 Windows：" + o.root) +
            L"执行组件存储修复。" +
            (o.sourceKind == servicing::RepairSourceKind::WindowsUpdate
                 ? L"\n来源：Windows "
                   L"Update\n需要时联网获取修复内容，可能使用计量网络并产生较大流量；不会覆盖系统策略。"
             : o.sourceKind == servicing::RepairSourceKind::Default
                 ? L"\n来源：自动"
                 : L"\n来源：" + o.source +
                       (o.sourceKind == servicing::RepairSourceKind::Wim
                            ? L"\n映像序号：" + std::to_wstring(o.sourceIndex)
                            : L"")) +
            (chain ? L"\n后续：SFC 修复并完整复验（当前阶段后停止）" : L"") + L"\n\n是否继续？";
        if (MessageBoxW(window, text.c_str(), L"修复受损", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) !=
            IDYES)
            return;
    }
    if (!o.online) {
        if (!ResolvePartition(ROOT, o.root))
            return;
        sfc.root = o.root;
    }
    SetBusy(true);
    Append(kind == 3 ? L"开始验证受损。" : L"开始修复受损。");
    std::thread([o, sfc, chain, kind] {
        auto done = new Finished;
        done->kind = kind;
        try {
            if (chain) {
                auto preflight = servicing::ValidateSfcTarget(sfc);
                if (preflight.hr != S_OK) {
                    done->hr = preflight.hr;
                    done->detail = L"尚未启动 CBS：SFC 目标参数预检失败。\r\n" + preflight.detail;
                    PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
                    return;
                }
            }
            if (cancelled) {
                done->hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
                done->detail = L"已停止，未启动维护。";
                PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
                return;
            }
            auto r = IsolatedCbs(o);
            done->hr = r.hr;
            done->detail = r.stage + L"：" + r.detail;
            if (SUCCEEDED(r.hr) && kind == 3) {
                static const wchar_t *health[] = {
                    L"CBS 本次扫描未报告组件存储受损。请结合实际异常文件核对结果。",
                    L"CBS 报告组件存储受损，可尝试修复。", L"CBS 报告组件存储存在不可修复的问题。"};
                if (r.health >= 0 && r.health < 3)
                    done->detail = health[r.health];
                else {
                    done->hr = E_FAIL;
                    done->detail = L"扫描没有返回有效健康状态。";
                }
            }
            if (kind == 4 && r.hr == S_OK)
                done->detail += L"\r\nCBS 维护已返回成功，请再次验证受损，并核对实际异常文件。";
            if (r.imageStateUnknown)
                done->detail += L"\r\n操作后的映像状态尚未确认，请重新验证。";
            if (!r.cbsLog.empty())
                done->detail += L"\r\nCBS 日志：" + r.cbsLog;
            if (chain && r.hr == S_OK && r.requiredActionAvailable && r.requiredAction != 0) {
                done->hr = S_FALSE;
                done->detail += L"\r\nCBS 要求后续系统动作（原始值：" + std::to_wstring(r.requiredAction) +
                                L"）。请先按 Windows 提示完成待处理动作，再运行 SFC；本次未启动 SFC。";
            } else if (chain) {
                if (r.hr == S_OK && !r.imageStateUnknown && (kind == 4 || (r.health >= 0 && r.health <= 2))) {
                    Report(-1, L"CBS 工作进程已退出，修复来源清理完成；准备 SFC。");
                    done->detail = L"【组件存储】" + done->detail;
                    RunSfcStages(sfc, *done);
                    if (kind == 3 && r.health > 0 && done->hr == S_OK)
                        done->hr = S_FALSE;
                } else
                    done->detail += L"\r\nCBS 阶段未明确成功，未启动 SFC。";
            }
        } catch (...) {
            done->hr = E_FAIL;
            done->detail = L"宿主通信异常；目标状态尚未确认。";
        }
        PostMessageW(window, WM_FINISHED, 0, LPARAM(done));
    }).detach();
}

void Visibility(int id, bool show) {
    ShowWindow(GetDlgItem(window, id), show ? SW_SHOW : SW_HIDE);
}
void Card(int x, int y, int w, int h) {
    cards.push_back(RECT{x, Y(y), x + w, Y(y + h)});
}
void Layout() {
    RECT r;
    GetClientRect(window, &r);
    int w = r.right, h = r.bottom;
    layoutScale = std::min(1., double(h) / 916.);
    cards.clear();
    int x = 208, cw = w - 232;
    Place(501, x, 25, cw, 46);
    Place(NAV_WIM, 0, 124, 180, 54);
    Place(NAV_REPAIR, 0, 178, 180, 54);
    for (auto q : wimControls)
        ShowWindow(q, selectedTab == 0 ? SW_SHOW : SW_HIDE);
    for (auto q : cbsControls)
        ShowWindow(q, selectedTab == 1 ? SW_SHOW : SW_HIDE);
    int bottom = 0;
    if (expandedLog) {
        for (auto q : wimControls)
            ShowWindow(q, SW_HIDE);
        for (auto q : cbsControls)
            ShowWindow(q, SW_HIDE);
        bottom = 78;
    } else if (selectedTab == 0) {
        bool boot = Checked(BOOT);
        int firmware = int(SendDlgItemMessageW(window, FIRMWARE, CB_GETCURSEL, 0, 0));
        bool mbr = false;
        auto selected = selectedPartitions.find(DEST);
        if (selected != selectedPartitions.end() && Text(DEST) == selected->second.Caption())
            mbr = selected->second.type.rfind(L"MBR", 0) == 0;
        else if (servicing::DriveRootSyntax(Text(DEST))) {
            servicing::LocalRoot volume;
            if (servicing::InspectRoot(Text(DEST), volume) == S_OK)
                mbr = volume.style == 0;
        }
        bool biosTool = boot && (firmware == 1 || (firmware == 0 && mbr));
        Card(x, 92, cw, boot ? (biosTool ? 324 : 272) : 220);
        Place(510, x + 22, 114, 82, 24);
        Place(SOURCE, x + 112, 108, cw - 300, 34);
        Place(401, w - 188, 108, 72, 34);
        Place(LOAD, w - 104, 108, 80, 34);
        Place(511, x + 22, 166, 82, 24);
        Place(IMAGES, x + 112, 158, cw - 136, 220);
        Place(512, x + 22, 218, 82, 24);
        Place(DEST, x + 112, 210, cw - 216, 34);
        Place(402, w - 104, 210, 80, 34);
        Place(WTG, x + 22, 262, 210, 30);
        Place(BOOT, x + 252, 262, 210, 30);
        for (int id :
             std::vector<int>{514, BOOTPART, PART_BOOT, 515, FIRMWARE, 529, BOOT_TOOL, BOOT_TOOL_BROWSE})
            Visibility(id, boot);
        for (int id : std::vector<int>{529, BOOT_TOOL, BOOT_TOOL_BROWSE})
            Visibility(id, biosTool);
        if (boot) {
            Place(514, x + 22, 318, 82, 24);
            Place(BOOTPART, x + 112, 310, cw - 442, 34);
            Place(PART_BOOT, x + cw - 318, 310, 80, 34);
            Place(515, x + cw - 222, 318, 72, 24);
            Place(FIRMWARE, x + cw - 144, 310, 120, 180);
            Place(529, x + 22, 370, 82, 24);
            Place(BOOT_TOOL, x + 112, 362, cw - 216, 34);
            Place(BOOT_TOOL_BROWSE, w - 104, 362, 80, 34);
        }
        bottom = boot ? (biosTool ? 416 : 364) : 312;
        Place(APPLY, x, bottom + 18, 168, 40);
    } else {
        bool offline = !Checked(ONLINE), cbs = UsesCbs();
        int y = 92;
        int th = offline ? 120 : 72;
        Card(x, y, cw, th);
        Place(ONLINE, x + 22, y + 20, 270, 30);
        for (int id : std::vector<int>{520, ROOT, 404})
            Visibility(id, offline);
        if (offline) {
            Place(520, x + 22, y + 76, 82, 24);
            Place(ROOT, x + 112, y + 68, cw - 216, 34);
            Place(404, w - 104, y + 68, 80, 34);
        }
        y += th + 16;
        int wh = cbs ? 112 : 72;
        Card(x, y, cw, wh);
        Place(526, x + 22, y + 24, 82, 24);
        int mw = (cw - 160) / 3;
        Place(WORKFLOW, x + 112, y + 16, mw, 36);
        Place(MODE_BOTH, x + 124 + mw, y + 16, mw, 36);
        Place(MODE_SFC, x + 136 + 2 * mw, y + 16, mw, 36);
        Visibility(FULL_PAYLOAD, cbs);
        if (cbs)
            Place(FULL_PAYLOAD, x + 22, y + 66, cw - 44, 30);
        y += wh + 16;
        int kind = int(SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0));
        int sh = cbs && kind == 2 ? 164 : cbs && kind == 1 ? 116 : cbs && kind == 3 ? 104 : 72;
        if (cbs)
            Card(x, y, cw, sh);
        for (int id : std::vector<int>{521, SOURCE_KIND})
            Visibility(id, cbs);
        Place(521, x + 22, y + 24, 82, 24);
        Place(SOURCE_KIND, x + 112, y + 16, cw - 136, 180);
        Visibility(528, cbs && kind == 3);
        if (cbs && kind == 3)
            Place(528, x + 22, y + 64, cw - 44, 26);
        bool custom = cbs && (kind == 1 || kind == 2), wim = cbs && kind == 2;
        for (int id : std::vector<int>{523, REPAIR_PATH, REPAIR_BROWSE})
            Visibility(id, custom);
        for (int id : std::vector<int>{524, REPAIR_IMAGES, REPAIR_LOAD})
            Visibility(id, wim);
        if (custom) {
            Place(523, x + 22, y + 72, 82, 24);
            Place(REPAIR_PATH, x + 112, y + 64, cw - (wim ? 300 : 216), 34);
            Place(REPAIR_BROWSE, w - (wim ? 188 : 104), y + 64, wim ? 72 : 80, 34);
            if (wim) {
                Place(REPAIR_LOAD, w - 104, y + 64, 80, 34);
                Place(524, x + 22, y + 120, 82, 24);
                Place(REPAIR_IMAGES, x + 112, y + 112, cw - 136, 200);
            }
        }
        bottom = cbs ? y + sh : y - 16;
        Place(SCAN, x, bottom + 18, 146, 40);
        Place(RESTORE, x + 162, bottom + 18, 168, 40);
    }
    int sy = bottom + 76;
    MoveWindow(status, x, Y(sy), cw - 160, 26, TRUE);
    Place(CANCEL, w - 160, sy - 7, 136, 34);
    MoveWindow(progress, x, Y(sy + 36), cw - 88, 18, TRUE);
    Place(PROGRESS_TEXT, w - 104, sy + 34, 80, 26);
    int ly = sy + 70;
    Place(527, x, ly + 6, 82, 26);
    Place(LOG_BRIEF, w - 588, ly, 60, 32);
    Place(LOG_FULL, w - 520, ly, 60, 32);
    Place(LOG_READABLE, w - 452, ly, 130, 32);
    Place(LOG_EXPAND, w - 314, ly, 96, 32);
    Place(LOG_COPY, w - 210, ly, 70, 32);
    Place(LOG_OPEN, w - 132, ly, 108, 32);
    int top = Y(ly + 44), height = std::max(72, h - top - 20);
    MoveWindow(logEdit, x, top, cw, height, TRUE);
    ShowWindow(logEdit, readableLog ? SW_HIDE : SW_SHOW);
    Visibility(LOG_TREE, readableLog);
    Visibility(LOG_DETAIL, readableLog);
    Visibility(LOG_SUMMARY, readableLog);
    Visibility(LOG_SOURCE_SUMMARY, readableLog);
    if (readableLog) {
        bool compact = height < 190;
        int detail = height < 120 ? 0 : std::min(110, height / 4), head = compact ? 30 : 58;
        ShowWindow(GetDlgItem(window, LOG_SOURCE_SUMMARY), compact ? SW_HIDE : SW_SHOW);
        ShowWindow(logDetail, detail ? SW_SHOW : SW_HIDE);
        MoveWindow(GetDlgItem(window, LOG_SUMMARY), x + 10, top + 4, cw - 20, 24, TRUE);
        MoveWindow(GetDlgItem(window, LOG_SOURCE_SUMMARY), x + 10, top + 29, cw - 20, 24, TRUE);
        MoveWindow(logTree, x, top + head, cw, std::max(24, height - detail - head - 8), TRUE);
        MoveWindow(logDetail, x, top + height - detail, cw, detail, TRUE);
    }
    RedrawWindow(window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}
void Init() {
    font = CreateFontW(-17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY,
                       0, L"Microsoft YaHei UI");
    heading = CreateFontW(-32, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0,
                          CLEARTYPE_QUALITY, 0, L"Microsoft YaHei UI Light");
    smallFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0,
                            CLEARTYPE_QUALITY, 0, L"Segoe UI");
    monoFont = CreateFontW(
        -15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0,
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") ? L"Noto Sans Mono CJK SC"
                                                                           : L"Consolas");
    bgBrush = CreateSolidBrush(RGB(243, 246, 250));
    surfaceBrush = CreateSolidBrush(RGB(255, 255, 255));
    navBrush = CreateSolidBrush(RGB(15, 38, 61));
    logBrush = CreateSolidBrush(RGB(20, 31, 45));
    Control(L"STATIC", L"镜像释放", 0, 501, -1);
    SendDlgItemMessageW(window, 501, WM_SETFONT, WPARAM(heading), TRUE);
    Control(L"BUTTON", L"镜像释放", WS_TABSTOP, NAV_WIM, -1);
    Control(L"BUTTON", L"系统修复", WS_TABSTOP, NAV_REPAIR, -1);
    for (auto row : std::vector<std::pair<int, const wchar_t *>>{{510, L"WIM 文件"},
                                                                 {511, L"映像版本"},
                                                                 {512, L"目标分区"},
                                                                 {514, L"启动分区"},
                                                                 {515, L"启动方式"}})
        Control(L"STATIC", row.second, 0, row.first, 0);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, SOURCE, 0);
    Control(L"BUTTON", L"浏览", WS_TABSTOP, 401, 0);
    Control(L"BUTTON", L"读取", WS_TABSTOP, LOAD, 0);
    Control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, IMAGES, 0);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, DEST, 0);
    Control(L"BUTTON", L"分区…", WS_TABSTOP, 402, 0);
    Control(L"BUTTON", L"WindowsToGo", BS_AUTOCHECKBOX | WS_TABSTOP, WTG, 0);
    Control(L"BUTTON", L"写入引导", BS_AUTOCHECKBOX | WS_TABSTOP, BOOT, 0);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, BOOTPART, 0);
    Control(L"BUTTON", L"分区…", WS_TABSTOP, PART_BOOT, 0);
    Control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP, FIRMWARE, 0);
    for (auto text : {L"自动", L"BIOS / MBR", L"UEFI / GPT"})
        SendDlgItemMessageW(window, FIRMWARE, CB_ADDSTRING, 0, LPARAM(text));
    SendDlgItemMessageW(window, FIRMWARE, CB_SETCURSEL, 0, 0);
    Control(L"STATIC", L"BIOS 工具", 0, 529, 0);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, BOOT_TOOL, 0);
    Control(L"BUTTON", L"浏览", WS_TABSTOP, BOOT_TOOL_BROWSE, 0);
    Control(L"BUTTON", L"释放映像", WS_TABSTOP, APPLY, 0);
    Control(L"BUTTON", L"当前 Windows", BS_AUTOCHECKBOX | WS_TABSTOP, ONLINE, 1);
    SendDlgItemMessageW(window, ONLINE, BM_SETCHECK, BST_CHECKED, 0);
    Control(L"STATIC", L"系统分区", 0, 520, 1);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, ROOT, 1);
    Control(L"BUTTON", L"分区…", WS_TABSTOP, 404, 1);
    Control(L"STATIC", L"维护方式", 0, 526, 1);
    Control(L"BUTTON", L"CBS", WS_TABSTOP, WORKFLOW, 1);
    Control(L"BUTTON", L"CBS + SFC", WS_TABSTOP, MODE_BOTH, 1);
    Control(L"BUTTON", L"SFC", WS_TABSTOP, MODE_SFC, 1);
    Control(L"BUTTON", L"完整负载校验", BS_AUTOCHECKBOX | WS_TABSTOP, FULL_PAYLOAD, 1);
    SendDlgItemMessageW(window, FULL_PAYLOAD, BM_SETCHECK, BST_CHECKED, 0);
    Control(L"STATIC", L"修复源", 0, 521, 1);
    Control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP, SOURCE_KIND, 1);
    for (auto text : {L"自动", L"Windows 目录", L"WIM 映像", L"Windows Update"})
        SendDlgItemMessageW(window, SOURCE_KIND, CB_ADDSTRING, 0, LPARAM(text));
    SendDlgItemMessageW(window, SOURCE_KIND, CB_SETCURSEL, 0, 0);
    Control(L"STATIC", L"需要时联网获取修复内容；受系统策略控制。", 0, 528, 1);
    Control(L"STATIC", L"路径", 0, 523, 1);
    Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, REPAIR_PATH, 1);
    Control(L"BUTTON", L"浏览", WS_TABSTOP, REPAIR_BROWSE, 1);
    Control(L"BUTTON", L"读取", WS_TABSTOP, REPAIR_LOAD, 1);
    Control(L"STATIC", L"映像版本", 0, 524, 1);
    Control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, REPAIR_IMAGES, 1);
    Control(L"BUTTON", L"验证受损", WS_TABSTOP, SCAN, 1);
    Control(L"BUTTON", L"修复受损", WS_TABSTOP, RESTORE, 1);
    status = Control(L"STATIC", L"就绪", SS_LEFTNOWORDWRAP, STATUS, -1);
    Control(L"BUTTON", L"停止", WS_TABSTOP, CANCEL, -1);
    Control(L"STATIC", L"", SS_RIGHT, PROGRESS_TEXT, -1);
    progress = Control(PROGRESS_CLASSW, L"", 0, PROGRESS, -1);
    SetWindowTheme(progress, L"", L"");
    SendMessageW(progress, PBM_SETBARCOLOR, 0, RGB(0, 120, 212));
    Control(L"STATIC", L"运行日志", 0, 527, -1);
    for (auto button : std::vector<std::pair<int, const wchar_t *>>{{LOG_BRIEF, L"简略"},
                                                                    {LOG_FULL, L"完整"},
                                                                    {LOG_READABLE, L"完整（易读）"},
                                                                    {LOG_EXPAND, L"展开日志"},
                                                                    {LOG_COPY, L"复制"},
                                                                    {LOG_OPEN, L"打开日志"}})
        Control(L"BUTTON", button.second, WS_TABSTOP, button.first, -1);
    logEdit = Control(L"EDIT", L"",
                      WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                      LOG, -1);
    SendMessageW(logEdit, WM_SETFONT, WPARAM(monoFont), TRUE);
    SetWindowTheme(logEdit, L"", L"");
    SendMessageW(logEdit, EM_SETLIMITTEXT, 2 * 1024 * 1024, 0);
    logTree =
        Control(WC_TREEVIEWW, L"",
                TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | WS_TABSTOP | WS_VSCROLL,
                LOG_TREE, -1);
    SetWindowTheme(logTree, L"Explorer", nullptr);
    TreeView_SetBkColor(logTree, RGB(255, 255, 255));
    TreeView_SetTextColor(logTree, RGB(40, 58, 76));
    SendMessageW(logTree, TVM_SETITEMHEIGHT, 28, 0);
    SendMessageW(logTree, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    logDetail = Control(L"EDIT", L"选择记录以查看完整内容。来源请求与下载记录需结合会话及结果核对。",
                        ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_TABSTOP, LOG_DETAIL, -1);
    SendMessageW(logDetail, EM_SETLIMITTEXT, 131072, 0);
    Control(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS, LOG_SUMMARY, -1);
    Control(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS, LOG_SOURCE_SUMMARY, -1);
    if (!preview) {
        wchar_t folder[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, folder))) {
            auto base = std::wstring(folder) + L"\\ADism";
            CreateDirectoryW(base.c_str(), nullptr);
            base += L"\\Logs";
            CreateDirectoryW(base.c_str(), nullptr);
            SYSTEMTIME t;
            GetLocalTime(&t);
            wchar_t name[96];
            swprintf(name, 96, L"\\%04u%02u%02u-%02u%02u%02u-%lu-full.log", t.wYear, t.wMonth, t.wDay,
                     t.wHour, t.wMinute, t.wSecond, GetCurrentProcessId());
            GUID logId{};
            wchar_t logGuid[40]{};
            if (CoCreateGuid(&logId) == S_OK && StringFromGUID2(logId, logGuid, 40))
                sessionLog = base + name + L"-" + logGuid + L".log";
        }
    }
    workbench::StartLog(sessionLog);
    if (preview) {
        SetDlgItemTextW(window, SOURCE, L"D:\\Images\\install.wim");
        SetDlgItemTextW(window, DEST, L"G:\\");
        SetDlgItemTextW(window, BOOTPART, L"S:\\");
        SetDlgItemTextW(window, ROOT, L"G:\\");
        servicing::WimImage image;
        image.index = 3;
        image.name = L"Windows 11 Pro";
        image.major = 10;
        image.build = 26100;
        images.push_back(image);
        SendDlgItemMessageW(window, IMAGES, CB_ADDSTRING, 0, LPARAM(L"3 — Windows 11 Pro"));
        SendDlgItemMessageW(window, IMAGES, CB_SETCURSEL, 0, 0);
        SetDlgItemTextW(window, REPAIR_PATH, L"D:\\Images\\install.wim");
        repairImages = images;
        SendDlgItemMessageW(window, REPAIR_IMAGES, CB_ADDSTRING, 0, LPARAM(L"3 — Windows 11 Pro"));
        SendDlgItemMessageW(window, REPAIR_IMAGES, CB_SETCURSEL, 0, 0);
        Append(L"[预览] 已载入 Windows 11 Pro");
        workbench::Log(L"映像版本=10.0.26100.2314; Architecture=x64; Edition=Professional", false, L"映像",
                       workbench::LogLevel::Detail);
        Append(L"[预览] 来源检查完成");
        workbench::Log(L"[示例] 目标=当前 Windows; 请求来源=Windows Update", false, L"配置",
                       workbench::LogLevel::Detail);
        workbench::Log(L"[示例] Download completed; bytes=229116491", false, L"CBS",
                       workbench::LogLevel::Detail);
        workbench::Log(L"[示例] Total Detected Corruption: 1; Total Repaired Corruption: 1", false, L"CBS",
                       workbench::LogLevel::Detail);
        workbench::Log(L"[示例] 2026-10-30 CBS Client: Manual; InnerFlags=2", false, L"CBS",
                       workbench::LogLevel::Detail);
    }
    for (int id : {DEST, BOOTPART, ROOT})
        SendDlgItemMessageW(window, id, EM_SETCUEBANNER, TRUE, LPARAM(L"输入盘符根目录，或点击“分区…”"));
    SendDlgItemMessageW(window, BOOT_TOOL, EM_SETCUEBANNER, TRUE,
                        LPARAM(L"仅 BIOS 使用：微软 bootsect.exe；系统目录或安装光盘可自动查找"));
    SetTimer(window, 1, 250, nullptr);
    RefreshEnabled();
    Layout();
}
void DrawButton(DRAWITEMSTRUCT *d) {
    int id = int(d->CtlID);
    bool nav = id == NAV_WIM || id == NAV_REPAIR;
    bool selected = (id == WORKFLOW && Flow() == 0) || (id == MODE_BOTH && Flow() == 1) ||
                    (id == MODE_SFC && Flow() == 2) || (id == NAV_WIM && selectedTab == 0) ||
                    (id == NAV_REPAIR && selectedTab == 1) || (id == LOG_FULL && fullLog && !readableLog) ||
                    (id == LOG_BRIEF && !fullLog && !readableLog) || (id == LOG_READABLE && readableLog);
    bool primary = id == APPLY || id == RESTORE;
    bool disabled = (d->itemState & ODS_DISABLED) != 0;
    COLORREF bg = nav                   ? (selected ? RGB(0, 120, 212) : RGB(15, 38, 61))
                  : primary || selected ? RGB(0, 120, 212)
                                        : RGB(255, 255, 255);
    if (d->itemState & ODS_SELECTED)
        bg = RGB(0, 86, 153);
    if (disabled && !nav)
        bg = RGB(230, 235, 241);
    auto brush = CreateSolidBrush(bg);
    FillRect(d->hDC, &d->rcItem, brush);
    DeleteObject(brush);
    if (!nav && !primary && !selected) {
        auto pen = CreatePen(PS_SOLID, 1, RGB(195, 207, 220));
        auto old = SelectObject(d->hDC, pen);
        auto b = SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
        Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
        SelectObject(d->hDC, b);
        SelectObject(d->hDC, old);
        DeleteObject(pen);
    }
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, disabled                     ? RGB(130, 142, 154)
                         : nav || primary || selected ? RGB(255, 255, 255)
                                                      : RGB(30, 55, 79));
    SelectObject(d->hDC, font);
    auto text = Text(d->hwndItem);
    auto r = d->rcItem;
    DrawTextW(d->hDC, text.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (d->itemState & ODS_FOCUS) {
        InflateRect(&r, -4, -4);
        DrawFocusRect(d->hDC, &r);
    }
}
void Paint() {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(window, &ps);
    RECT r;
    GetClientRect(window, &r);
    FillRect(dc, &r, bgBrush);
    RECT nav{0, 0, 180, r.bottom};
    FillRect(dc, &nav, navBrush);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, heading);
    RECT brand{24, 30, 168, 105};
    DrawTextW(dc, L"ADism", -1, &brand, DT_LEFT | DT_TOP);
    for (auto card : cards) {
        RECT shadow = card;
        OffsetRect(&shadow, 0, 2);
        auto shade = CreateSolidBrush(RGB(226, 232, 239));
        FillRect(dc, &shadow, shade);
        DeleteObject(shade);
        FillRect(dc, &card, surfaceBrush);
        RECT accent = card;
        accent.right = accent.left + 3;
        auto blue = CreateSolidBrush(RGB(0, 120, 212));
        FillRect(dc, &accent, blue);
        DeleteObject(blue);
    }
    for (int id : std::vector<int>{SOURCE, DEST, BOOTPART, ROOT, REPAIR_PATH}) {
        auto child = GetDlgItem(window, id);
        if (!IsWindowVisible(child))
            continue;
        RECT e;
        GetWindowRect(child, &e);
        MapWindowPoints(nullptr, window, reinterpret_cast<POINT *>(&e), 2);
        InflateRect(&e, 1, 1);
        auto pen = CreatePen(PS_SOLID, 1, GetFocus() == child ? RGB(0, 120, 212) : RGB(204, 215, 227));
        auto old = SelectObject(dc, pen);
        auto brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, e.left, e.top, e.right, e.bottom);
        SelectObject(dc, brush);
        SelectObject(dc, old);
        DeleteObject(pen);
    }
    EndPaint(window, &ps);
}
void LaunchWorkflow(bool repair) {
    if (busy || preview)
        return;
    int flow = Flow(), sourceKind = int(SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0));
    Append((repair ? L"准备修复：" : L"准备检测：") + std::wstring(flow == 0   ? L"CBS"
                                                                   : flow == 1 ? L"CBS → SFC"
                                                                               : L"SFC"));
    std::wstring config = L"目标=" + std::wstring(Checked(ONLINE) ? L"当前 Windows" : Text(ROOT));
    if (UsesSfc() && !Checked(ONLINE))
        config += L"; SFC 离线启动目录=所选 Windows 分区";
    if (!repair)
        config += L"; 来源=检测不使用修复源";
    else if (!UsesCbs())
        config += L"; 来源=目标组件存储（SFC）";
    else {
        config += L"; 请求来源=" + Text(SOURCE_KIND);
        if (sourceKind == 1 || sourceKind == 2)
            config += L"; 路径=" + Text(REPAIR_PATH);
        if (sourceKind == 2)
            config += L"; 映像=" + Text(REPAIR_IMAGES);
    }
    workbench::Log(config, false, L"配置", workbench::LogLevel::Detail);
    Launch(flow == 2 ? (repair ? 7 : 6) : (repair ? 4 : 3));
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE:
        window = h;
        Init();
        return 0;
    case WM_SIZE:
        if (logEdit)
            Layout();
        return 0;
    case WM_GETMINMAXINFO:
        reinterpret_cast<MINMAXINFO *>(l)->ptMinTrackSize = {980, 780};
        return 0;
    case WM_NOTIFY:
        if (reinterpret_cast<NMHDR *>(l)->idFrom == LOG_TREE) {
            auto hdr = reinterpret_cast<NMHDR *>(l);
            if (hdr->code == NM_CUSTOMDRAW) {
                auto draw = reinterpret_cast<NMTVCUSTOMDRAW *>(l);
                if (draw->nmcd.dwDrawStage == CDDS_PREPAINT)
                    return CDRF_NOTIFYITEMDRAW;
                if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    auto key = draw->nmcd.lItemlParam;
                    if (key == -5)
                        draw->clrText = RGB(166, 91, 0);
                    else if (key == -2 || key == -3 || key == -4)
                        draw->clrText = RGB(0, 104, 184);
                    return CDRF_DODEFAULT;
                }
                return CDRF_DODEFAULT;
            }
            if (hdr->code == TVN_ITEMEXPANDINGW) {
                auto n = reinterpret_cast<NMTREEVIEWW *>(l);
                if (n->action == TVE_EXPAND && n->itemNew.lParam < 0) {
                    size_t i = size_t(-n->itemNew.lParam - 1);
                    if (i < displayedGroups.size())
                        FillGroup(i);
                }
            }
            if (hdr->code == TVN_SELCHANGEDW) {
                auto n = reinterpret_cast<NMTREEVIEWW *>(l);
                auto data = n->itemNew.lParam;
                if (data > 0) {
                    size_t i = size_t(data - 1) >> 20, j = size_t(data - 1) & ((1 << 20) - 1);
                    if (i < displayedGroups.size() && j < displayedGroups[i].rows.size())
                        SetWindowTextW(logDetail, displayedGroups[i].rows[j].c_str());
                } else if (data < 0) {
                    size_t i = size_t(-data - 1);
                    if (i < displayedGroups.size()) {
                        auto text =
                            displayedGroups[i].title + L"：" + std::to_wstring(displayedGroups[i].total) +
                            L" 条记录。记录数不代表损坏 / 修复文件数；原生统计保留在“结果与引擎统计”中。";
                        SetWindowTextW(logDetail, text.c_str());
                    }
                }
            }
            return 0;
        }
        if (reinterpret_cast<NMHDR *>(l)->idFrom == TAB &&
            reinterpret_cast<NMHDR *>(l)->code == TCN_SELCHANGE)
            ShowPage(TabCtrl_GetCurSel(tab));
        return 0;
    case WM_APP + 0x66:
        if (preview && w < 2) {
            ShowPage(int(w));
            return 0;
        }
        break;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case NAV_WIM:
            if (!busy)
                ShowPage(0);
            return 0;
        case NAV_REPAIR:
            if (!busy)
                ShowPage(1);
            return 0;
        case LOG_BRIEF:
        case LOG_FULL:
        case LOG_READABLE:
            readableLog = LOWORD(w) == LOG_READABLE;
            fullLog = LOWORD(w) != LOG_BRIEF;
            RenderLog(true);
            Layout();
            return 0;
        case LOG_EXPAND:
            expandedLog = !expandedLog;
            SetDlgItemTextW(window, LOG_EXPAND, expandedLog ? L"返回配置" : L"展开日志");
            Layout();
            return 0;
        case LOG_COPY:
            CopyLog();
            return 0;
        case LOG_OPEN: {
            auto p = workbench::LogPath();
            if (!p.empty())
                ShellExecuteW(window, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        }
        case WORKFLOW:
        case MODE_BOTH:
        case MODE_SFC:
            if (!busy) {
                flowSelection = LOWORD(w) == WORKFLOW ? 0 : LOWORD(w) == MODE_BOTH ? 1 : 2;
                RefreshEnabled();
                Layout();
            }
            return 0;
        case BOOT_TOOL_BROWSE:
            BrowseFile(BOOT_TOOL);
            return 0;
        case PART_BOOT:
            ChoosePartition(BOOTPART);
            return 0;
        case 401:
            BrowseFile();
            return 0;
        case 402:
            ChoosePartition(DEST);
            return 0;
        case 404:
            ChoosePartition(ROOT);
            return 0;
        case REPAIR_BROWSE:
            if (SendDlgItemMessageW(window, SOURCE_KIND, CB_GETCURSEL, 0, 0) == 2)
                BrowseFile(REPAIR_PATH);
            else
                BrowseFolder(REPAIR_PATH);
            return 0;
        case REPAIR_LOAD:
            Launch(5);
            return 0;
        case SOURCE_KIND:
            if (HIWORD(w) == CBN_SELCHANGE) {
                RefreshEnabled();
                Layout();
            }
            return 0;
        case LOAD:
            Launch(1);
            return 0;
        case APPLY:
            Launch(2);
            return 0;
        case SCAN:
            LaunchWorkflow(false);
            return 0;
        case RESTORE:
            LaunchWorkflow(true);
            return 0;
        case CANCEL:
            cancelled = true;
            Append(activePhase == 2 ? L"已请求本阶段后停止，等待 SFC 自然结束。"
                                    : L"已请求停止，等待引擎和来源清理。");
            RefreshEnabled();
            return 0;
        case FIRMWARE:
            if (HIWORD(w) != CBN_SELCHANGE)
                return 0;
            [[fallthrough]];
        case BOOT:
        case ONLINE:
        case FULL_PAYLOAD:
            RefreshEnabled();
            Layout();
            return 0;
        case IMAGES:
            if (HIWORD(w) == CBN_SELCHANGE)
                RefreshEnabled();
            return 0;
        case SOURCE:
        case DEST:
        case ROOT:
        case REPAIR_PATH:
        case BOOTPART:
            if (HIWORD(w) == EN_SETFOCUS || HIWORD(w) == EN_KILLFOCUS) {
                InvalidateRect(window, nullptr, FALSE);
                if (LOWORD(w) == DEST && HIWORD(w) == EN_KILLFOCUS)
                    Layout();
            }
            break;
        }
        break;
    case WM_DRAWITEM:
        DrawButton(reinterpret_cast<DRAWITEMSTRUCT *>(l));
        return TRUE;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(w);
        HWND child = reinterpret_cast<HWND>(l);
        int id = GetDlgCtrlID(child);
        SetBkMode(dc, OPAQUE);
        if (id == LOG) {
            SetTextColor(dc, RGB(209, 223, 237));
            SetBkColor(dc, RGB(20, 31, 45));
            return LRESULT(logBrush);
        }
        SetTextColor(dc, IsWindowEnabled(child) ? RGB(40, 58, 76) : RGB(144, 154, 166));
        if (id == 501 || id == STATUS || id == 527 || id == PROGRESS_TEXT) {
            SetBkColor(dc, RGB(243, 246, 250));
            return LRESULT(bgBrush);
        }
        SetBkColor(dc, RGB(255, 255, 255));
        return LRESULT(surfaceBrush);
    }
    case WM_TIMER:
        if (w == 1)
            RenderLog();
        return 0;
    case WM_PHASE:
        if (busy) {
            RefreshEnabled();
            DisplayProgress(-1);
        }
        return 0;
    case WM_PROGRESS: {
        auto n = reinterpret_cast<Notice *>(l);
        if (busy) {
            DisplayProgress(n->percent);
            auto text = workbench::DisplayText(n->text);
            SetWindowTextW(status, text.c_str());
        }
        delete n;
        return 0;
    }
    case WM_FINISHED: {
        auto r = reinterpret_cast<Finished *>(l);
        SetBusy(false);
        SendMessageW(progress, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(progress, GWL_STYLE, GetWindowLongPtrW(progress, GWL_STYLE) & ~PBS_MARQUEE);
        if (r->kind == 1 && SUCCEEDED(r->hr)) {
            images = std::move(r->images);
            catalogPath = r->detail;
            SendDlgItemMessageW(window, IMAGES, CB_RESETCONTENT, 0, 0);
            for (auto &i : images) {
                auto label = std::to_wstring(i.index) + L" — " + i.name;
                SendDlgItemMessageW(window, IMAGES, CB_ADDSTRING, 0, LPARAM(label.c_str()));
            }
            if (!images.empty())
                SendDlgItemMessageW(window, IMAGES, CB_SETCURSEL, 0, 0);
            r->detail = L"已读取 " + std::to_wstring(images.size()) + L" 个映像。";
            RefreshEnabled();
        }
        if (r->kind == 5 && r->hr == S_OK) {
            repairImages = std::move(r->images);
            repairCatalogPath = r->detail;
            SendDlgItemMessageW(window, REPAIR_IMAGES, CB_RESETCONTENT, 0, 0);
            for (const auto &image : repairImages) {
                auto label = std::to_wstring(image.index) + L" — " + image.name + L" (" +
                             std::to_wstring(image.build) + L"." + std::to_wstring(image.revision) + L")";
                SendDlgItemMessageW(window, REPAIR_IMAGES, CB_ADDSTRING, 0, LPARAM(label.c_str()));
            }
            if (!repairImages.empty())
                SendDlgItemMessageW(window, REPAIR_IMAGES, CB_SETCURSEL, 0, 0);
            r->detail = L"已读取 " + std::to_wstring(repairImages.size()) + L" 个修复来源映像；请核对版本。";
            RefreshEnabled();
        }
        if (partitionCleanupPending) {
            if (r->hr == S_OK)
                r->hr = S_FALSE;
            r->detail += L"\r\n临时盘符尚未全部清理，请核对分区日志；本次不标记为完全完成。";
        }
        bool complete = r->hr == S_OK;
        auto line = std::wstring(complete           ? L"完成 · "
                                 : r->hr == S_FALSE ? L"部分完成 · "
                                                    : L"未完成 · ") +
                    L"[" + Hex(r->hr) + L"] " + r->detail;
        workbench::Log(line, true, L"结果",
                       complete ? workbench::LogLevel::Info : workbench::LogLevel::Warning);
        RenderLog();
        SetWindowTextW(status, complete           ? ((r->kind == 4 || r->kind == 6 || r->kind == 7)
                                                         ? L"维护已返回，请核对各阶段结果"
                                                         : L"操作完成")
                               : r->hr == S_FALSE ? L"部分完成，请查看日志"
                                                  : L"操作未完成，请查看日志");
        if (complete)
            SendMessageW(progress, PBM_SETPOS, 100, 0);
        SetDlgItemTextW(window, PROGRESS_TEXT, complete ? L"已结束" : L"未完成");
        if ((r->kind != 1 && r->kind != 5) || FAILED(r->hr))
            MessageBoxW(h, line.c_str(), L"任务结果", complete ? MB_ICONINFORMATION : MB_ICONWARNING);
        delete r;
        return 0;
    }
    case WM_CLOSE:
        if (busy) {
            MessageBoxW(h,
                        activePhase == 2
                            ? L"SFC 仍在运行。可请求本阶段后停止，并等待系统工具自然结束；不能强制关闭维护。"
                            : L"任务仍在运行。请先取消并等待维护引擎返回。",
                        L"任务进行中", MB_ICONINFORMATION);
            return 0;
        }
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        partitionAccess.Clear();
        KillTimer(h, 1);
        DeleteObject(font);
        DeleteObject(heading);
        DeleteObject(smallFont);
        DeleteObject(monoFont);
        DeleteObject(bgBrush);
        DeleteObject(surfaceBrush);
        DeleteObject(navBrush);
        DeleteObject(logBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int SfcWorker(int count, wchar_t **args) {
    HANDLE pipe = nullptr, event = nullptr;
    servicing::SfcOptions o;
    bool online = false, offline = false;
    unsigned operations = 0;
    try {
        for (int i = 1; i < count; ++i) {
            std::wstring a = args[i];
            if (a == L"--sfc-worker")
                continue;
            if (a == L"--pipe" && i + 1 < count)
                pipe = reinterpret_cast<HANDLE>(uintptr_t(std::stoull(args[++i])));
            else if (a == L"--cancel-handle" && i + 1 < count)
                event = reinterpret_cast<HANDLE>(uintptr_t(std::stoull(args[++i])));
            else if (a == L"--online") {
                o.online = true;
                online = true;
            } else if (a == L"--offline" && i + 1 < count) {
                o.online = false;
                offline = true;
                o.root = args[++i];
            } else if (a == L"--repair") {
                if (++operations > 1)
                    return 2;
                o.operation = servicing::SfcOperation::Repair;
            } else if (a == L"--verify") {
                if (++operations > 1)
                    return 2;
                o.operation = servicing::SfcOperation::Verify;
            } else
                return 2;
        }
    } catch (...) {
        return 2;
    }
    DWORD flags = 0;
    if (operations != 1 || online == offline || !pipe || !event || !GetHandleInformation(pipe, &flags) ||
        !GetHandleInformation(event, &flags))
        return 2;
    SetHandleInformation(pipe, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(event, HANDLE_FLAG_INHERIT, 0);
    auto send = [&](const std::wstring &s) {
        auto bytes = Utf8(s + L"\n");
        size_t offset = 0;
        while (offset < bytes.size()) {
            DWORD n = 0;
            if (!WriteFile(pipe, bytes.data() + offset, DWORD(bytes.size() - offset), &n, nullptr) || !n)
                return;
            offset += n;
        }
    };
    std::atomic_bool stop{WaitForSingleObject(event, 0) == WAIT_OBJECT_0}, done{false};
    std::thread watcher([&] {
        while (!done) {
            if (WaitForSingleObject(event, 50) == WAIT_OBJECT_0) {
                stop = true;
                break;
            }
        }
    });
    servicing::SfcResult r;
    try {
        r = servicing::RunSfc(o, stop, [&](int p, const std::wstring &s) {
            const std::wstring prefix = L"SFC 输出日志：";
            if (s.rfind(prefix, 0) == 0)
                send(L"L\t" + Escape(s.substr(prefix.size())));
            else
                send(L"P\t" + std::to_wstring(p) + L"\t" + Escape(s));
        });
    } catch (...) {
        r.hr = E_FAIL;
        r.detail = L"SFC 宿主异常，结果尚未确认。";
    }
    done = true;
    watcher.join();
    send(L"S\t" + Hex(r.hr) + L"\t" + std::to_wstring(r.exitCode) + L"\t" + (r.started ? L"1" : L"0") +
         L"\t" + (r.processExited ? L"1" : L"0") + L"\t" + (r.stopRequested ? L"1" : L"0") + L"\t" +
         std::to_wstring(int(r.report)) + L"\t" + Escape(r.stage) + L"\t" + Escape(r.detail) + L"\t" +
         Escape(r.rawLog) + L"\t" + Escape(r.textLog) + L"\t" + Escape(r.offLog) + L"\tend");
    CloseHandle(pipe);
    CloseHandle(event);
    return r.hr == S_OK ? 0 : 1;
}
int Worker(int count, wchar_t **args) {
    HANDLE pipe = nullptr, event = nullptr;
    servicing::CbsOptions o;
    unsigned pipeCount = 0, eventCount = 0, targetCount = 0, operationCount = 0, sourceCount = 0,
             indexCount = 0, modeCount = 0;
    auto number = [](const std::wstring &s) -> unsigned long long {
        if (s.empty() || !std::all_of(s.begin(), s.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
            throw std::invalid_argument("number");
        return std::stoull(s);
    };
    try {
        for (int i = 1; i < count; ++i) {
            std::wstring a = args[i];
            if (a == L"--cbs-worker")
                continue;
            if (a == L"--pipe" && i + 1 < count) {
                if (++pipeCount > 1)
                    return 2;
                pipe = reinterpret_cast<HANDLE>(uintptr_t(number(args[++i])));
            } else if (a == L"--cancel-handle" && i + 1 < count) {
                if (++eventCount > 1)
                    return 2;
                event = reinterpret_cast<HANDLE>(uintptr_t(number(args[++i])));
            } else if (a == L"--online") {
                if (++targetCount > 1)
                    return 2;
                o.online = true;
            } else if (a == L"--offline" && i + 1 < count) {
                if (++targetCount > 1)
                    return 2;
                o.online = false;
                o.root = args[++i];
            } else if (a == L"--scan") {
                if (++operationCount > 1)
                    return 2;
                o.operation = servicing::CbsOperation::Scan;
            } else if (a == L"--restore") {
                if (++operationCount > 1)
                    return 2;
                o.operation = servicing::CbsOperation::Restore;
            } else if (a == L"--source-directory" && i + 1 < count) {
                if (++sourceCount > 1)
                    return 2;
                o.sourceKind = servicing::RepairSourceKind::Directory;
                o.source = args[++i];
            } else if (a == L"--source-wim" && i + 1 < count) {
                if (++sourceCount > 1)
                    return 2;
                o.sourceKind = servicing::RepairSourceKind::Wim;
                o.source = args[++i];
            } else if (a == L"--source-index" && i + 1 < count) {
                auto value = number(args[++i]);
                if (++indexCount > 1 || !value || value > 0xffffffffu)
                    return 2;
                o.sourceIndex = unsigned(value);
            } else if (a == L"--windows-update") {
                if (++sourceCount > 1)
                    return 2;
                o.sourceKind = servicing::RepairSourceKind::WindowsUpdate;
            } else if (a == L"--local-only") {
                if (++sourceCount > 1)
                    return 2;
                o.sourceKind = servicing::RepairSourceKind::LocalOnly;
            } else if (a == L"--full-payload") {
                if (++modeCount > 1)
                    return 2;
                o.fullPayloadCheck = true;
            } else if (a == L"--automatic-compat") {
                if (++modeCount > 1)
                    return 2;
                o.fullPayloadCheck = false;
            } else
                return 2;
        }
    } catch (...) {
        return 2;
    }
    DWORD flags = 0;
    if (pipeCount != 1 || eventCount != 1 || targetCount != 1 || operationCount != 1 || !pipe || !event ||
        !GetHandleInformation(pipe, &flags) || !GetHandleInformation(event, &flags) ||
        GetFileType(pipe) != FILE_TYPE_PIPE || WaitForSingleObject(event, 0) == WAIT_FAILED)
        return 2;
    if ((o.sourceKind == servicing::RepairSourceKind::Wim) != (indexCount == 1))
        return 2;
    if (!SetHandleInformation(pipe, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(event, HANDLE_FLAG_INHERIT, 0))
        return 2;
    std::mutex writeMutex;
    auto send = [&](const std::wstring &s) {
        std::lock_guard<std::mutex> lock(writeMutex);
        auto u = Utf8(s + L"\n");
        size_t offset = 0;
        while (offset < u.size()) {
            DWORD written = 0;
            if (!WriteFile(pipe, u.data() + offset, DWORD(u.size() - offset), &written, nullptr) || !written)
                return;
            offset += written;
        }
    };
    std::atomic_bool cancel{WaitForSingleObject(event, 0) == WAIT_OBJECT_0}, done{false};
    std::thread watcher([&] {
        while (!done) {
            auto state = WaitForSingleObject(event, 50);
            if (state == WAIT_OBJECT_0 || state == WAIT_FAILED) {
                cancel = true;
                break;
            }
        }
    });
    servicing::CbsResult r;
    try {
        r = servicing::RunCbs(o, cancel, [&](int p, const std::wstring &s) {
            send(L"P\t" + std::to_wstring(p) + L"\t" + Escape(s));
        });
    } catch (...) {
        r.hr = E_FAIL;
        r.detail = L"CBS 宿主发生异常。";
        r.imageStateUnknown = true;
    }
    done = true;
    watcher.join();
    send(L"R\t" + Hex(r.hr) + L"\t" + std::to_wstring(r.health) + L"\t" + (r.cancelRequested ? L"1" : L"0") +
         L"\t" + (r.imageStateUnknown ? L"1" : L"0") + L"\t" + Escape(r.stage) + L"\t" + Escape(r.detail) +
         L"\t" + Escape(r.cbsLog) + L"\t" + std::to_wstring(r.requiredAction) + L"\t" +
         (r.requiredActionAvailable ? L"1" : L"0"));
    CloseHandle(pipe);
    CloseHandle(event);
    return r.hr == S_OK ? 0 : 1;
}

} // namespace
int WINAPI wWinMain(HINSTANCE h, HINSTANCE, LPWSTR, int show) {
    int count = 0;
    auto args = CommandLineToArgvW(GetCommandLineW(), &count);
    int initialTab = 0;
    for (int i = 1; i < count; ++i) {
        std::wstring a = args[i];
        if (a == L"--sfc-worker") {
            int code = SfcWorker(count, args);
            LocalFree(args);
            return code;
        }
        if (a == L"--cbs-worker") {
            int code = Worker(count, args);
            LocalFree(args);
            return code;
        }
        if (a == L"--self-test") {
            int failures = workbench::LogSelfTest() + servicing::SfcSelfTest() + servicing::CbsSelfTest() +
                           servicing::WimSelfTest() + servicing::BootSelfTest() + servicing::SafetySelfTest();
            LocalFree(args);
            return failures ? 1 : 0;
        }
        if (a == L"--preview")
            preview = true;
        if (a == L"--preview-tab=1")
            initialTab = 1;
    }
    LocalFree(args);
    instance = h;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX ic = {sizeof(ic), ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_TREEVIEW_CLASSES |
                                               ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&ic);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = h;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ADism.Main";
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"ADism 0.7.0", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                CW_USEDEFAULT, CW_USEDEFAULT, 1080, 980, nullptr, nullptr, h, nullptr);
    if (!hwnd)
        return 1;
    ShowPage(initialTab);
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!busy && msg.message == WM_KEYDOWN && msg.wParam == 'N' && (GetKeyState(VK_CONTROL) & 0x8000)) {
            ShowPage(0);
            continue;
        }
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    CoUninitialize();
    return int(msg.wParam);
}
