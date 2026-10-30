// SPDX-License-Identifier: GPL-3.0-only
#include "ui_log.h"
#include <algorithm>
#include <atomic>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>
#include <cwctype>
namespace workbench {
namespace {
std::mutex mutex;
std::wstring path;
std::deque<std::wstring> fullRows, briefRows;
size_t fullSize = 0, briefSize = 0;
uint64_t revision = 0;
bool clipped = false, fileFailed = false;
struct LogFile {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~LogFile() {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
} logFile;
constexpr size_t limit = 1024 * 1024;
const wchar_t *groupNames[] = {L"运行概览",       L"请求来源与路径", L"取源 / 下载记录（不等同于成功命中）",
                               L"结果与引擎统计", L"警告与错误",     L"CBS 明细",
                               L"SFC 明细",       L"文件与进度",     L"其他明细"};
struct GroupBuffer {
    std::deque<std::wstring> rows;
    size_t size = 0;
    uint64_t total = 0;
    bool clipped = false;
};
std::array<GroupBuffer, 9> groups;
std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), towlower);
    return s;
}
int Group(const std::wstring &text, const std::wstring &scope, LogLevel level, bool brief) {
    auto s = Lower(text);
    if (scope == L"配置" || scope == L"分区" || s.find(L"向 cbs 添加修复来源") != s.npos ||
        s.find(L"请求来源") != s.npos || s.find(L"来源策略") != s.npos ||
        s.find(L"明确请求 windows update") != s.npos)
        return 1;
    if (scope.find(L"结果") != scope.npos || s.find(L"corruption:") != s.npos ||
        s.find(L"repaired:") != s.npos || s.find(L"summary:") != s.npos ||
        s.find(L"total detected") != s.npos || s.find(L"total repaired") != s.npos ||
        s.find(L"operation result") != s.npos || s.find(L"[sr] verify complete") != s.npos)
        return 3;
    if (level == LogLevel::Error || level == LogLevel::Warning || s.find(L", error") != s.npos ||
        s.find(L", warning") != s.npos || s.find(L"(f)") != s.npos)
        return 4;
    if (s.find(L"download") != s.npos || s.find(L"acquirer") != s.npos || s.find(L"source:") != s.npos ||
        s.find(L"source path") != s.npos || s.find(L"repair source") != s.npos ||
        s.find(L"from source") != s.npos)
        return 2;
    if (brief)
        return 0;
    if (scope == L"CBS")
        return 5;
    if (scope == L"SFC")
        return 6;
    if (scope == L"引擎")
        return 7;
    return 8;
}
void StoreGroup(int index, const std::wstring &row) {
    auto &g = groups[index];
    ++g.total;
    g.size += row.size();
    g.rows.push_back(row);
    while ((g.size > 262144 || g.rows.size() > 2000) && g.rows.size() > 1) {
        g.size -= g.rows.front().size();
        g.rows.pop_front();
        g.clipped = true;
    }
}

std::string Utf8(const std::wstring &s) {
    if (s.empty())
        return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0, nullptr, nullptr);
    std::string b(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), b.data(), n, nullptr, nullptr);
    return b;
}
void Push(std::deque<std::wstring> &rows, size_t &size, std::wstring line) {
    size += line.size();
    rows.push_back(std::move(line));
    while (size > limit && rows.size() > 1) {
        size -= rows.front().size();
        rows.pop_front();
        clipped = true;
    }
}
std::wstring FirstLine(const std::wstring &s) {
    auto n = s.find_first_of(L"\r\n");
    auto r = s.substr(0, n);
    return r.size() > 200 ? r.substr(0, 200) + L"…" : r;
}
struct Decoder {
    int encoding = 1;
    std::vector<unsigned char> carry;
    std::wstring Read(const unsigned char *b, size_t n, bool final = false) {
        if (n)
            carry.insert(carry.end(), b, b + n);
        std::wstring out;
        if (encoding == 2 || encoding == 3) {
            size_t used = carry.size() & ~size_t(1);
            if (!final && used >= 2) {
                auto c = encoding == 2 ? wchar_t(carry[used - 2] | (carry[used - 1] << 8))
                                       : wchar_t(carry[used - 1] | (carry[used - 2] << 8));
                if (c >= 0xd800 && c <= 0xdbff)
                    used -= 2;
            }
            for (size_t i = 0; i < used; i += 2)
                out += encoding == 2 ? wchar_t(carry[i] | (carry[i + 1] << 8))
                                     : wchar_t(carry[i + 1] | (carry[i] << 8));
            carry.erase(carry.begin(), carry.begin() + used);
        } else {
            size_t used = carry.size();
            int chars = 0;
            bool valid = false;
            for (size_t tail = 0; tail <= 3 && tail <= carry.size(); ++tail) {
                used = carry.size() - tail;
                chars =
                    used ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                               reinterpret_cast<char *>(carry.data()), int(used), nullptr, 0)
                         : 0;
                if (chars || !used) {
                    valid = true;
                    break;
                }
            }
            if (valid) {
                out.resize(chars);
                if (chars)
                    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<char *>(carry.data()),
                                        int(used), out.data(), chars);
                carry.erase(carry.begin(), carry.begin() + used);
            } else {
                out = L"\r\n[日志片段无法解码，请查看原文件]\r\n";
                carry.clear();
            }
        }
        if (final && !carry.empty()) {
            out += L"\r\n[原文件包含未完成的字符片段]\r\n";
            carry.clear();
        }
        return out;
    }
};
} // namespace
std::wstring DisplayText(std::wstring text) {
    const std::wstring old = L"Dism++";
    size_t pos = 0;
    while (pos + old.size() <= text.size()) {
        bool match = true;
        for (size_t i = 0; i < old.size(); ++i)
            if (towlower(text[pos + i]) != towlower(old[i])) {
                match = false;
                break;
            }
        if (match) {
            text.replace(pos, old.size(), L"维护客户端");
            pos += 5;
        } else
            ++pos;
    }
    return text;
}
void StartLog(const std::wstring &p) {
    std::lock_guard<std::mutex> lock(mutex);
    path = p;
    groups = {};
    fullRows.clear();
    briefRows.clear();
    fullSize = briefSize = 0;
    clipped = false;
    fileFailed = false;
    if (logFile.h != INVALID_HANDLE_VALUE) {
        CloseHandle(logFile.h);
        logFile.h = INVALID_HANDLE_VALUE;
    }
    if (!path.empty()) {
        logFile.h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (logFile.h == INVALID_HANDLE_VALUE)
            fileFailed = true;
    }
    ++revision;
}
void Log(const std::wstring &input, bool brief, const std::wstring &scope, LogLevel level) {
    auto text = DisplayText(input);
    if (text.empty())
        return;
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t stamp[32];
    swprintf(stamp, 32, L"%02u:%02u:%02u.%03u", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    const wchar_t *levels[] = {L"INFO", L"TRACE", L"WARN", L"ERROR"};
    auto row = std::wstring(stamp) + L" [" + levels[int(level)] + L"] [" + scope + L"] " + text + L"\r\n";
    std::lock_guard<std::mutex> lock(mutex);
    if (logFile.h != INVALID_HANDLE_VALUE) {
        auto b = Utf8(row);
        size_t pos = 0;
        while (pos < b.size()) {
            DWORD n = 0;
            if (!WriteFile(logFile.h, b.data() + pos, DWORD(std::min<size_t>(b.size() - pos, 65536)), &n,
                           nullptr) ||
                !n) {
                fileFailed = true;
                break;
            }
            pos += n;
        }
    }

    if (row.size() > 65536)
        row = row.substr(0, 65536) + L"\r\n[长记录已缩略，可在已成功保存的原始日志文件中核对]\r\n";
    StoreGroup(Group(text, scope, level, brief), row);
    Push(fullRows, fullSize, std::move(row));
    if (brief)
        Push(briefRows, briefSize, std::wstring(stamp) + L"  " + FirstLine(text) + L"\r\n");
    ++revision;
}
std::wstring LogText(bool full) {
    std::lock_guard<std::mutex> lock(mutex);
    std::wstring s;
    if (fileFailed)
        s = L"[文件日志保存失败，可复制当前缓冲记录]\r\n";
    if (clipped)
        s += fileFailed || path.empty() ? L"[显示最近记录，早期缓冲已移除]\r\n"
                                        : L"[显示最近记录，完整内容已保存至日志文件]\r\n";
    for (const auto &r : full ? fullRows : briefRows)
        s += r;
    return s;
}
std::vector<LogGroup> StructuredLog() {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<LogGroup> result;
    for (size_t i = 0; i < groups.size(); ++i) {
        const auto &g = groups[i];
        result.push_back({groupNames[i], g.total, g.clipped, {g.rows.begin(), g.rows.end()}});
    }
    if (fileFailed)
        result[4].rows.push_back(L"文件日志保存失败，请复制当前记录。");
    return result;
}
std::wstring StructuredLogText() {
    auto groups = StructuredLog();
    std::wstring text = L"来源配置是请求；取源记录需结合会话和结果核对。记录数不是修复文件数。\r\n";
    for (const auto &g : groups) {
        text += L"\r\n【" + g.title + L"】 " + std::to_wstring(g.total) + L" 条记录\r\n";
        if (g.clipped)
            text += L"[仅保留最近分组记录，如原始日志文件保存成功，可在那里核对全部内容]\r\n";
        for (const auto &r : g.rows)
            text += r;
    }
    return text;
}
std::wstring LogPath() {
    std::lock_guard<std::mutex> lock(mutex);
    return path;
}
uint64_t LogRevision() {
    std::lock_guard<std::mutex> lock(mutex);
    return revision;
}
uint64_t FileLogOffset(const std::wstring &p) {
    HANDLE f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    LARGE_INTEGER n{};
    GetFileSizeEx(f, &n);
    CloseHandle(f);
    return uint64_t(n.QuadPart);
}
struct FileLogFollower::State {
    std::wstring file, scope;
    uint64_t offset;
    std::atomic_bool stop{false};
    Decoder decoder;
    std::wstring pending;
    bool detected = false;
    DWORD serial = 0, low = 0, high = 0;
    FILETIME created{};
    bool identified = false;
    std::thread thread;
    State(std::wstring p, uint64_t o, std::wstring s) : file(std::move(p)), scope(std::move(s)), offset(o) {
        thread = std::thread([this] {
            try {
                while (!stop) {
                    Pump();
                    for (int i = 0; i < 5 && !stop; ++i)
                        Sleep(100);
                }
                int drained = 0;
                while (drained < 32 && Pump())
                    ++drained;
                if (drained == 32)
                    Log(L"结束时日志积压较大，剩余内容请查看原文件：" + file, true, scope, LogLevel::Warning);
                auto tail = decoder.Read(nullptr, 0, true);
                pending += tail;
                if (!pending.empty())
                    Log(pending, false, scope, LogLevel::Detail);
            } catch (...) {
            }
        });
    }
    ~State() {
        stop = true;
        if (thread.joinable())
            thread.join();
    }
    bool Pump() {
        HANDLE f =
            CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE)
            return false;
        struct Close {
            HANDLE h;
            ~Close() {
                CloseHandle(h);
            }
        } close{f};
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(f, &info)) {
            if (identified &&
                (serial != info.dwVolumeSerialNumber || low != info.nFileIndexLow ||
                 high != info.nFileIndexHigh || CompareFileTime(&created, &info.ftCreationTime) != 0)) {
                offset = 0;
                decoder.carry.clear();
                detected = false;
            }
            created = info.ftCreationTime;
            serial = info.dwVolumeSerialNumber;
            low = info.nFileIndexLow;
            high = info.nFileIndexHigh;
            identified = true;
        }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(f, &size))
            return false;
        if (uint64_t(size.QuadPart) < offset) {
            offset = 0;
            decoder.carry.clear();
            detected = false;
        }
        if (uint64_t(size.QuadPart) <= offset)
            return false;
        if (!detected) {
            unsigned char probe[128]{};
            DWORD n = 0;
            if (!ReadFile(f, probe, sizeof(probe), &n, nullptr) || !n)
                return false;
            size_t odd = 0, even = 0;
            for (DWORD i = 0; i + 1 < n; i += 2) {
                odd += probe[i + 1] == 0;
                even += probe[i] == 0;
            }
            decoder.encoding = (n >= 2 && probe[0] == 0xff && probe[1] == 0xfe)   ? 2
                               : (n >= 2 && probe[0] == 0xfe && probe[1] == 0xff) ? 3
                               : odd >= 2 && odd > even * 3                       ? 2
                               : even >= 2 && even > odd * 3                      ? 3
                                                                                  : 1;
            detected = true;
        }
        LARGE_INTEGER at{};
        at.QuadPart = offset;
        if (!SetFilePointerEx(f, at, nullptr, FILE_BEGIN))
            return false;
        unsigned char bytes[65536];
        DWORD got = 0;
        if (!ReadFile(f, bytes, sizeof(bytes), &got, nullptr) || !got)
            return false;
        offset += got;
        auto text = decoder.Read(bytes, got);
        pending += text;
        size_t line;
        while ((line = pending.find_first_of(L"\r\n")) != std::wstring::npos) {
            auto row = pending.substr(0, line);
            pending.erase(0, line + 1);
            if (!row.empty())
                Log(row, false, scope, LogLevel::Detail);
        }
        if (pending.size() > 131072) {
            Log(L"[超长原生记录省略，请查看原文件]", false, scope, LogLevel::Warning);
            pending.clear();
        }
        return true;
    }
};
FileLogFollower::FileLogFollower(const std::wstring &p, uint64_t offset, const std::wstring &s)
    : state_(new State(p, offset, s)) {
    Log(L"引擎日志：" + p + L"；起始字节=" + std::to_wstring(offset), false, s, LogLevel::Detail);
}
FileLogFollower::~FileLogFollower() = default;
int LogSelfTest() {
    int n = 0;
    Decoder d;
    d.encoding = 2;
    unsigned char a[] = {0x2d, 0x4e, 0x87, 0x65};
    std::wstring s;
    for (auto b : a)
        s += d.Read(&b, 1);
    if (s != L"中文")
        ++n;
    Decoder u;
    unsigned char utf[] = {0xe4, 0xb8, 0xad};
    s.clear();
    for (auto b : utf)
        s += u.Read(&b, 1);
    if (s != L"中")
        ++n;
    StartLog(L"");
    Log(L"阶段摘要", true);
    Log(L"细节字段", false, L"TEST", LogLevel::Detail);
    if (LogText(false).find(L"细节字段") != std::wstring::npos ||
        LogText(true).find(L"细节字段") == std::wstring::npos)
        ++n;
    StartLog(L"");
    Log(L"请求来源=Windows Update", false, L"配置", LogLevel::Detail);
    Log(L"Download completed; bytes=123", false, L"CBS", LogLevel::Detail);
    Log(L"Total Detected Corruption: 1", false, L"CBS", LogLevel::Detail);
    Log(L"HRESULT=0x800F081F", false, L"CBS 结果", LogLevel::Detail);
    Log(L"error", false, L"任务", LogLevel::Error);
    Log(L"native", false, L"CBS", LogLevel::Detail);
    auto groups = StructuredLog();
    if (groups.size() != 9 || groups[1].total != 1 || groups[2].total != 1 || groups[3].total != 2 ||
        groups[4].total != 1 || groups[5].total != 1)
        ++n;
    if (StructuredLogText().find(L"非修复") == std::wstring::npos &&
        StructuredLogText().find(L"不是修复") == std::wstring::npos)
        ++n;
    for (int i = 0; i < 2200; ++i)
        Log(L"detail", false, L"CBS", LogLevel::Detail);
    groups = StructuredLog();
    if (groups[5].total != 2201 || groups[5].rows.size() != 2000 || !groups[5].clipped)
        ++n;
    StartLog(L"");
    if (StructuredLog()[5].total)
        ++n;
    return n;
}
} // namespace workbench
