// SPDX-License-Identifier: GPL-3.0-only
#include "sfc_backend.h"
#include "safety.h"
#include <shlobj.h>
#include <sddl.h>
#include <winioctl.h>
#include <wbemidl.h>
#include <thread>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cwctype>
namespace servicing {
namespace {
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE v) : h(v) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    ~Handle() {
        Close();
    }
    void Close() {
        if (h && h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
    bool valid() const {
        return h && h != INVALID_HANDLE_VALUE;
    }
};
HRESULT Error(DWORD e = GetLastError()) {
    return HRESULT_FROM_WIN32(e ? e : ERROR_GEN_FAILURE);
}
void Report(const SfcProgress &fn, const std::wstring &s) {
    if (fn)
        try {
            fn(-1, s);
        } catch (...) {
        }
}
bool EqualI(const std::wstring &a, const std::wstring &b) {
    return !_wcsicmp(a.c_str(), b.c_str());
}
std::wstring Join(const std::wstring &a, const std::wstring &b) {
    return a + (a.empty() || a.back() == L'\\' ? L"" : L"\\") + b;
}
bool RootSyntax(const std::wstring &p) {
    return (p.size() == 2 || p.size() == 3) && iswalpha(p[0]) && p[1] == L':' &&
           (p.size() == 2 || p[2] == L'\\') && p[0] < 128;
}
std::wstring Root(const std::wstring &p) {
    return RootSyntax(p) ? std::wstring(1, wchar_t(towupper(p[0]))) + L":\\" : L"";
}
bool Reparse(const std::wstring &p) {
    std::wstring s = p;
    while (!s.empty()) {
        DWORD a = GetFileAttributesW(s.c_str());
        if (a == INVALID_FILE_ATTRIBUTES)
            return true;
        if (a & FILE_ATTRIBUTE_REPARSE_POINT)
            return true;
        if (s.size() <= 3)
            break;
        auto pos = s.find_last_of(L'\\');
        if (pos == s.npos)
            return true;
        s = s.substr(0, pos < 3 ? 3 : pos);
    }
    return false;
}
bool File(const std::wstring &p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
           !Reparse(p);
}
bool LocalVolume(const std::wstring &root, std::wstring &id) {
    wchar_t d[32768]{}, n[32768]{};
    if (!RootSyntax(root) || !QueryDosDeviceW(root.substr(0, 2).c_str(), d, 32768))
        return false;
    const std::wstring prefix = L"\\Device\\HarddiskVolume";
    std::wstring device = d;
    if (device.compare(0, prefix.size(), prefix) || device.size() == prefix.size() ||
        !std::all_of(device.begin() + prefix.size(), device.end(),
                     [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
        return false;
    if (!GetVolumeNameForVolumeMountPointW(root.c_str(), n, 32768) || Reparse(root))
        return false;
    id = n;
    return true;
}
bool Disks(const std::wstring &root, std::vector<DWORD> &disks) {
    Handle volume(CreateFileW((L"\\\\.\\" + root.substr(0, 2)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volume.valid())
        return false;
    alignas(VOLUME_DISK_EXTENTS) std::array<BYTE, 4096> buffer{};
    DWORD n = 0;
    if (!DeviceIoControl(volume.h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buffer.data(),
                         DWORD(buffer.size()), &n, nullptr) ||
        n < offsetof(VOLUME_DISK_EXTENTS, Extents))
        return false;
    auto e = reinterpret_cast<const VOLUME_DISK_EXTENTS *>(buffer.data());
    if (!e->NumberOfDiskExtents ||
        e->NumberOfDiskExtents > (n - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT))
        return false;
    for (DWORD i = 0; i < e->NumberOfDiskExtents; ++i)
        disks.push_back(e->Extents[i].DiskNumber);
    return true;
}
struct ComRef {
    IUnknown *p = nullptr;
    ~ComRef() {
        if (p)
            p->Release();
    }
};
bool UInt(const VARIANT &v, DWORD &out) {
    if (v.vt == VT_UI4 && v.ulVal != DWORD(-1)) {
        out = v.ulVal;
        return true;
    }
    if (v.vt == VT_I4 && v.lVal >= 0) {
        out = DWORD(v.lVal);
        return true;
    }
    return false;
}
HRESULT SystemPartitionsWmi(std::vector<std::pair<DWORD, DWORD>> &parts) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return hr;
    struct ComEnd {
        ~ComEnd() {
            CoUninitialize();
        }
    } com;
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        return hr;
    IWbemLocator *loc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                          reinterpret_cast<void **>(&loc));
    ComRef locRef;
    locRef.p = loc;
    if (FAILED(hr) || !loc)
        return FAILED(hr) ? hr : E_POINTER;
    BSTR space = SysAllocString(L"ROOT\\Microsoft\\Windows\\Storage");
    if (!space)
        return E_OUTOFMEMORY;
    IWbemServices *service = nullptr;
    hr = loc->ConnectServer(space, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr,
                            nullptr, &service);
    SysFreeString(space);
    ComRef serviceRef;
    serviceRef.p = service;
    if (FAILED(hr) || !service)
        return FAILED(hr) ? hr : E_POINTER;
    hr = CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr))
        return hr;
    BSTR language = SysAllocString(L"WQL"),
         query = SysAllocString(
             L"SELECT DiskNumber, PartitionNumber, IsSystem FROM MSFT_Partition WHERE IsSystem = TRUE");
    if (!language || !query) {
        SysFreeString(language);
        SysFreeString(query);
        return E_OUTOFMEMORY;
    }
    IEnumWbemClassObject *rows = nullptr;
    hr = service->ExecQuery(language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                            &rows);
    SysFreeString(language);
    SysFreeString(query);
    ComRef rowsRef;
    rowsRef.p = rows;
    if (FAILED(hr) || !rows)
        return FAILED(hr) ? hr : E_POINTER;
    hr = CoSetProxyBlanket(rows, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr))
        return hr;
    ULONGLONG deadline = GetTickCount64() + 6000;
    for (unsigned count = 0; count < 64; ++count) {
        if (GetTickCount64() >= deadline)
            return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        IWbemClassObject *row = nullptr;
        ULONG got = 0;
        hr = rows->Next(2000, 1, &row, &got);
        ComRef rowRef;
        rowRef.p = row;
        if (hr == WBEM_S_TIMEDOUT)
            return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        if (FAILED(hr))
            return hr;
        if (!got)
            return parts.empty() ? HRESULT_FROM_WIN32(ERROR_NOT_FOUND) : S_OK;
        if (!row)
            return E_POINTER;
        VARIANT system, disk, partition;
        VariantInit(&system);
        VariantInit(&disk);
        VariantInit(&partition);
        HRESULT a = row->Get(L"IsSystem", 0, &system, nullptr, nullptr),
                b = row->Get(L"DiskNumber", 0, &disk, nullptr, nullptr),
                c = row->Get(L"PartitionNumber", 0, &partition, nullptr, nullptr);
        DWORD d = 0, p = 0;
        bool valid = SUCCEEDED(a) && SUCCEEDED(b) && SUCCEEDED(c) && system.vt == VT_BOOL &&
                     system.boolVal == VARIANT_TRUE && UInt(disk, d) && UInt(partition, p) &&
                     d != DWORD(-1) && p != 0 && p != DWORD(-1);
        VariantClear(&system);
        VariantClear(&disk);
        VariantClear(&partition);
        if (!valid)
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        parts.emplace_back(d, p);
    }
    return HRESULT_FROM_WIN32(ERROR_MORE_DATA);
}
HRESULT ActualHostBoot(std::vector<std::pair<DWORD, DWORD>> &parts) {
    HRESULT result = E_FAIL;
    std::thread worker([&] {
        try {
            result = SystemPartitionsWmi(parts);
        } catch (...) {
            result = E_FAIL;
        }
    });
    worker.join();
    return result;
}
bool DevicePartition(const std::wstring &root, DWORD &disk, DWORD &partition) {
    Handle volume(CreateFileW((L"\\\\.\\" + root.substr(0, 2)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volume.valid())
        return false;
    STORAGE_DEVICE_NUMBER device{};
    DWORD n = 0;
    if (!DeviceIoControl(volume.h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &device, sizeof(device), &n,
                         nullptr) ||
        n < sizeof(device) || device.DeviceType != FILE_DEVICE_DISK || device.PartitionNumber == DWORD(-1) ||
        !device.PartitionNumber)
        return false;
    disk = device.DeviceNumber;
    partition = device.PartitionNumber;
    return true;
}
bool X64(const std::wstring &p) {
    Handle f(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (!f.valid())
        return false;
    IMAGE_DOS_HEADER dos{};
    DWORD n = 0;
    if (!ReadFile(f.h, &dos, sizeof(dos), &n, nullptr) || n != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
        return false;
    LARGE_INTEGER at{};
    at.QuadPart = dos.e_lfanew;
    DWORD sig = 0;
    IMAGE_FILE_HEADER pe{};
    return SetFilePointerEx(f.h, at, nullptr, FILE_BEGIN) && ReadFile(f.h, &sig, 4, &n, nullptr) && n == 4 &&
           sig == IMAGE_NT_SIGNATURE && ReadFile(f.h, &pe, sizeof(pe), &n, nullptr) && n == sizeof(pe) &&
           pe.Machine == IMAGE_FILE_MACHINE_AMD64;
}
std::wstring Quote(const std::wstring &s) {
    std::wstring out = L"\"";
    size_t slash = 0;
    for (wchar_t c : s) {
        if (c == L'\\') {
            ++slash;
            continue;
        }
        out.append(c == L'"' ? slash * 2 + 1 : slash, L'\\');
        out += c;
        slash = 0;
    }
    out.append(slash * 2, L'\\');
    return out + L"\"";
}
std::wstring Command(const std::wstring &exe, const SfcOptions &o, const std::wstring &offLog) {
    std::wstring c = Quote(exe) + (o.operation == SfcOperation::Verify ? L" /verifyonly" : L" /scannow");
    if (!o.online)
        c += L" " + Quote(L"/offbootdir=" + Root(o.bootRoot)) + L" " +
             Quote(L"/offwindir=" + Join(Root(o.root), L"Windows")) + L" " + Quote(L"/offlogfile=" + offLog);
    return c;
}
std::wstring Trim(std::wstring s) {
    auto a = s.find_first_not_of(L" \t\r\n\ufeff");
    if (a == s.npos)
        return {};
    auto b = s.find_last_not_of(L" \t\r\n\ufeff");
    return s.substr(a, b - a + 1);
}
SfcReport Terminal(const std::wstring &line) {
    auto s = Trim(line);
    const std::pair<const wchar_t *, SfcReport> lines[] = {
        {L"Windows Resource Protection did not find any integrity violations.", SfcReport::Clean},
        {L"Windows Resource Protection found corrupt files and successfully repaired them.",
         SfcReport::Repaired},
        {L"Windows Resource Protection found corrupt files but was unable to fix some of them.",
         SfcReport::Unrepaired},
        {L"Windows Resource Protection found integrity violations.", SfcReport::Unrepaired},
        {L"Windows Resource Protection could not perform the requested operation.", SfcReport::Unable},
        {L"Windows Resource Protection could not start the repair service.", SfcReport::Unable},
        {L"Windows 资源保护未找到任何完整性违规。", SfcReport::Clean},
        {L"Windows 资源保护未找到任何完整性冲突。", SfcReport::Clean},
        {L"Windows 资源保护找到了损坏文件并成功修复了它们。", SfcReport::Repaired},
        {L"Windows 资源保护找到了完整性违规。", SfcReport::Unrepaired},
        {L"Windows 资源保护找到了损坏文件，但无法修复其中的某些文件。", SfcReport::Unrepaired},
        {L"Windows 资源保护找到了损坏文件，但其中某些文件无法修复。", SfcReport::Unrepaired},
        {L"Windows 资源保护无法执行请求的操作。", SfcReport::Unable},
        {L"Windows 资源保护无法启动修复服务。", SfcReport::Unable}};
    for (const auto &x : lines)
        if (EqualI(s, x.first))
            return x.second;
    return SfcReport::Unknown;
}
struct Classifier {
    std::wstring line;
    SfcReport report = SfcReport::Unknown;
    bool conflict = false, overflow = false;
    void End() {
        auto r = overflow ? SfcReport::Unknown : Terminal(line);
        if (r != SfcReport::Unknown) {
            if (report != SfcReport::Unknown && report != r)
                conflict = true;
            report = r;
        }
        line.clear();
        overflow = false;
    }
    void Feed(const std::wstring &s) {
        for (auto c : s) {
            if (c == L'\r' || c == L'\n')
                End();
            else if (line.size() < 8192)
                line += c;
            else
                overflow = true;
        }
    }
    SfcReport Finish() {
        End();
        return conflict ? SfcReport::Unknown : report;
    }
};
enum class Encoding { Unknown, Utf8, Le, Be };
Encoding Detect(const std::vector<BYTE> &b, size_t &skip) {
    skip = 0;
    if (b.size() >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf) {
        skip = 3;
        return Encoding::Utf8;
    }
    if (b.size() >= 2 && b[0] == 0xff && b[1] == 0xfe) {
        skip = 2;
        return Encoding::Le;
    }
    if (b.size() >= 2 && b[0] == 0xfe && b[1] == 0xff) {
        skip = 2;
        return Encoding::Be;
    }
    size_t odd = 0, even = 0;
    for (size_t i = 0; i + 1 < b.size(); i += 2) {
        odd += b[i + 1] == 0;
        even += b[i] == 0;
    }
    if (odd >= 2 && odd > even * 3)
        return Encoding::Le;
    if (even >= 2 && even > odd * 3)
        return Encoding::Be;
    if (std::find(b.begin(), b.end(), BYTE(0)) != b.end())
        return Encoding::Unknown;
    int n = int(b.size());
    for (int tail = 0; tail < 4 && tail < n; ++tail)
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char *>(b.data()),
                                n - tail, nullptr, 0) > 0)
            return Encoding::Utf8;
    return b.empty() ? Encoding::Utf8 : Encoding::Unknown;
}
struct Decoder {
    Encoding encoding = Encoding::Unknown;
    std::vector<BYTE> carry;
    bool bad = false;
    wchar_t high = 0;
    std::wstring Feed(const BYTE *data, size_t size, bool final) {
        if (size)
            carry.insert(carry.end(), data, data + size);
        std::wstring out;
        if (encoding == Encoding::Le || encoding == Encoding::Be) {
            size_t count = carry.size() & ~size_t(1);
            for (size_t i = 0; i < count; i += 2) {
                wchar_t c = encoding == Encoding::Le ? wchar_t(carry[i] | (unsigned(carry[i + 1]) << 8))
                                                     : wchar_t(carry[i + 1] | (unsigned(carry[i]) << 8));
                if (high) {
                    if (c < 0xdc00 || c > 0xdfff)
                        bad = true;
                    out += high;
                    high = 0;
                } else if (c >= 0xdc00 && c <= 0xdfff)
                    bad = true;
                if (c >= 0xd800 && c <= 0xdbff)
                    high = c;
                else
                    out += c;
            }
            carry.erase(carry.begin(), carry.begin() + count);
            if (final && (!carry.empty() || high))
                bad = true;
        } else if (encoding == Encoding::Utf8) {
            size_t count = carry.size();
            int n = 0;
            for (size_t tail = 0; tail <= (final ? 0 : 3) && tail <= count; ++tail) {
                n = count - tail ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                       reinterpret_cast<const char *>(carry.data()),
                                                       int(count - tail), nullptr, 0)
                                 : 0;
                if (n || count == tail) {
                    count -= tail;
                    break;
                }
            }
            if (count && !n) {
                bad = true;
                carry.clear();
                return {};
            }
            if (n) {
                out.resize(n);
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    reinterpret_cast<const char *>(carry.data()), int(count), out.data(), n);
            }
            carry.erase(carry.begin(), carry.begin() + count);
            if (final && !carry.empty())
                bad = true;
        } else {
            bad = true;
            carry.clear();
        }
        return out;
    }
};
bool WriteAll(HANDLE h, const void *data, size_t size) {
    auto p = static_cast<const BYTE *>(data);
    while (size) {
        DWORD n = 0, want = DWORD(std::min<size_t>(size, 0x100000));
        if (!WriteFile(h, p, want, &n, nullptr) || !n)
            return false;
        size -= n;
        p += n;
    }
    return true;
}
bool Text(HANDLE file, const std::wstring &s) {
    if (s.empty())
        return true;
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0, nullptr,
                                nullptr);
    if (!n)
        return false;
    std::string out(n, 0);
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), int(s.size()), out.data(), n, nullptr,
                             nullptr))
        return false;
    return WriteAll(file, out.data(), out.size());
}
HRESULT DecodeLog(HANDLE raw, const std::wstring &path, SfcReport &report) {
    Handle text(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!text.valid())
        return Error();
    BYTE bom[] = {0xef, 0xbb, 0xbf};
    if (!WriteAll(text.h, bom, 3))
        return Error();
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(raw, zero, nullptr, FILE_BEGIN))
        return Error();
    std::vector<BYTE> probe(65536);
    DWORD count = 0;
    if (!ReadFile(raw, probe.data(), DWORD(probe.size()), &count, nullptr))
        return Error();
    probe.resize(count);
    size_t skip = 0;
    Decoder dec;
    dec.encoding = Detect(probe, skip);
    Classifier classifier;
    if (dec.encoding == Encoding::Unknown) {
        if (!Text(text.h, L"无法可靠判定 SFC 输出编码；请保留原始字节日志。\r\n"))
            return Error();
        report = SfcReport::Unknown;
        return FlushFileBuffers(text.h) ? HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) : Error();
    }
    auto consume = [&](const BYTE *b, size_t n, bool final) {
        std::wstring s = dec.Feed(b, n, final);
        classifier.Feed(s);
        return !dec.bad && Text(text.h, s);
    };
    if (!consume(probe.data() + skip, probe.size() - skip, false))
        return dec.bad ? HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) : Error();
    std::array<BYTE, 32768> b{};
    for (;;) {
        if (!ReadFile(raw, b.data(), DWORD(b.size()), &count, nullptr))
            return Error();
        if (!count)
            break;
        if (!consume(b.data(), count, false))
            return dec.bad ? HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) : Error();
    }
    if (!consume(nullptr, 0, true))
        return dec.bad ? HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) : Error();
    report = classifier.Finish();
    return FlushFileBuffers(text.h) ? S_OK : Error();
}
HRESULT OwnLogs(SfcResult &r, Handle &directory) {
    wchar_t base[32768]{};
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, base);
    if (FAILED(hr))
        return hr;
    if (Reparse(base))
        return E_ACCESSDENIED;
    std::wstring parent = Join(base, L"ADism");
    if (!CreateDirectoryW(parent.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return Error();
    if (Reparse(parent))
        return E_ACCESSDENIED;
    parent = Join(parent, L"SfcLogs");
    if (!CreateDirectoryW(parent.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return Error();
    if (Reparse(parent))
        return E_ACCESSDENIED;
    const std::wstring sddl = L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr))
        return Error();
    GUID id{};
    hr = CoCreateGuid(&id);
    wchar_t name[40]{};
    StringFromGUID2(id, name, 40);
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    std::wstring leaf = Join(parent, name);
    BOOL ok = SUCCEEDED(hr) && CreateDirectoryW(leaf.c_str(), &sa);
    DWORD e = GetLastError();
    LocalFree(sd);
    if (!ok)
        return FAILED(hr) ? hr : Error(e);
    directory.h =
        CreateFileW(leaf.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (!directory.valid() || Reparse(leaf))
        return E_ACCESSDENIED;
    r.rawLog = Join(leaf, L"console.raw");
    r.textLog = Join(leaf, L"console.utf8.txt");
    r.offLog = Join(leaf, L"offline-sfc.log");
    return S_OK;
}
HRESULT Outcome(SfcReport r) {
    switch (r) {
    case SfcReport::Clean:
    case SfcReport::Repaired:
        return S_OK;
    case SfcReport::Unrepaired:
        return HRESULT_FROM_WIN32(ERROR_FILE_CORRUPT);
    case SfcReport::Unable:
        return HRESULT_FROM_WIN32(ERROR_CAN_NOT_COMPLETE);
    default:
        return E_UNEXPECTED;
    }
}
} // namespace

HRESULT HostBootPartitions(std::vector<std::pair<DWORD, DWORD>> &parts) {
    return ActualHostBoot(parts);
}
std::wstring SfcReportText(SfcReport r) {
    switch (r) {
    case SfcReport::Clean:
        return L"SFC 报告未发现完整性问题";
    case SfcReport::Repaired:
        return L"SFC 报告已修复损坏文件";
    case SfcReport::Unrepaired:
        return L"SFC 报告仍有完整性问题";
    case SfcReport::Unable:
        return L"SFC 无法完成请求的操作";
    default:
        return L"SFC 最终结果无法确认";
    }
}
SfcResult ValidateSfcTarget(const SfcOptions &o) {
    SfcResult r;
    r.stage = L"验证 SFC 目标";
    auto fail = [&](HRESULT hr, const wchar_t *s) {
        r.hr = hr;
        r.detail = s;
        return r;
    };
#ifndef _WIN64
    return fail(E_NOTIMPL, L"当前只支持 x64 宿主 SFC。");
#endif
    if (o.operation != SfcOperation::Verify && o.operation != SfcOperation::Repair)
        return fail(E_INVALIDARG, L"无效的 SFC 操作。");
    wchar_t win[32768]{}, sys[32768]{};
    UINT wn = GetWindowsDirectoryW(win, 32768), sn = GetSystemDirectoryW(sys, 32768);
    if (!wn || wn >= 32768 || !sn || sn >= 32768)
        return fail(Error(), L"无法确定当前 Windows 的系统目录。");
    std::wstring host = win;
    if (host.size() < 3 || host[1] != L':' || host[2] != L'\\')
        return fail(E_NOTIMPL, L"无法可靠识别宿主 Windows 卷。");
    host = Root(host.substr(0, 3));
    std::wstring hostId;
    if (!LocalVolume(host, hostId))
        return fail(E_INVALIDARG, L"当前 Windows 卷不是可识别的实际本地卷。");
    const auto exe = Join(sys, L"sfc.exe");
    if (!File(exe) || !X64(exe))
        return fail(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT),
                    L"宿主 System32 缺少可信路径中的 x64 sfc.exe。");
    if (o.online) {
        if (!o.root.empty() && !EqualI(Root(o.root), host))
            return fail(E_INVALIDARG, L"在线模式不能指定其他 Windows 根目录。");
        if (!o.bootRoot.empty())
            return fail(E_INVALIDARG, L"在线模式不接受离线启动目录。");
        r.hr = S_OK;
        r.detail = L"当前运行的 Windows；使用宿主 System32\\sfc.exe。";
        return r;
    }
    auto target = Root(o.root), boot = Root(o.bootRoot);
    if (target.empty() || boot.empty())
        return fail(E_INVALIDARG, L"离线 Windows 和启动目录必须明确填写独立的盘符根目录，例如 G:\\、S:\\。");
    std::wstring targetId, bootId;
    if (!LocalVolume(target, targetId) || !LocalVolume(boot, bootId))
        return fail(E_INVALIDARG, L"不支持 UNC、SUBST、重解析路径或无法可靠识别的本地卷。");
    if (EqualI(targetId, hostId) || EqualI(bootId, hostId))
        return fail(E_INVALIDARG, L"离线 Windows 或启动目录不能映射到当前 Windows 卷。");
    if (!File(Join(target, L"Windows\\System32\\ntdll.dll")) ||
        !X64(Join(target, L"Windows\\System32\\ntdll.dll")) ||
        !File(Join(target, L"Windows\\System32\\ntoskrnl.exe")) ||
        !File(Join(target, L"Windows\\System32\\config\\SYSTEM")) ||
        !File(Join(target, L"Windows\\System32\\config\\SOFTWARE")))
        return fail(E_INVALIDARG, L"离线目标缺少完整的 x64 Windows 标志文件，或路径经过重解析点。");
    std::vector<DWORD> hostDisks, bootDisks, targetDisks;
    if (!Disks(host, hostDisks) || !Disks(boot, bootDisks) || !Disks(target, targetDisks))
        return fail(E_INVALIDARG, L"无法可靠识别离线启动目录与宿主系统的物理磁盘，已停止预检。");
    for (DWORD disk : bootDisks)
        if (std::find(hostDisks.begin(), hostDisks.end(), disk) != hostDisks.end())
            return fail(E_INVALIDARG, L"当前不支持离线启动目录与宿主 Windows 共用物理磁盘；不能使用宿主 ESP "
                                      L"或同盘双系统启动分区。");
    if (targetDisks.size() != 1 || bootDisks.size() != 1 || targetDisks[0] != bootDisks[0])
        return fail(E_NOTIMPL,
                    L"当前仅支持离线 Windows 与启动目录位于同一个独立物理磁盘；不支持跨盘启动布局。");
    DWORD bootDisk = 0, bootPartition = 0;
    if (!DevicePartition(boot, bootDisk, bootPartition) || bootDisk != bootDisks[0])
        return fail(E_INVALIDARG, L"无法可靠识别离线启动分区的磁盘号和分区号。");
    std::vector<std::pair<DWORD, DWORD>> hostBoot;
    HRESULT bootHr = ActualHostBoot(hostBoot);
    if (bootHr != S_OK)
        return fail(
            bootHr,
            L"无法通过 Storage WMI IsSystem 可靠识别宿主实际启动分区，已保守停止；不会猜测启动目录归属。");
    for (auto item : hostBoot)
        if (item.first == bootDisk && item.second == bootPartition)
            return fail(E_INVALIDARG,
                        L"离线启动目录是宿主当前实际启动分区（可能为跨盘 ESP），禁止用于离线 SFC。");
    DWORD fsFlags = 0;
    if (!GetVolumeInformationW(target.c_str(), nullptr, 0, nullptr, nullptr, &fsFlags, nullptr, 0))
        return fail(Error(), L"无法读取目标 Windows 卷属性。");
    if (fsFlags & FILE_READ_ONLY_VOLUME)
        return fail(E_ACCESSDENIED, L"SFC 目标卷只读，无法维护或加载其注册表。");
    bool bios = File(Join(boot, L"bootmgr")) && File(Join(boot, L"Boot\\BCD"));
    bool efi = File(Join(boot, L"EFI\\Microsoft\\Boot\\bootmgfw.efi")) &&
               File(Join(boot, L"EFI\\Microsoft\\Boot\\BCD"));
    if (!bios && !efi)
        return fail(E_INVALIDARG, L"启动目录缺少实际 Boot\\BCD+bootmgr 或 EFI\\Microsoft\\Boot 的 "
                                  L"BCD+bootmgfw.efi；不能以 Windows 目录代替启动目录。");
    r.hr = S_OK;
    r.detail = L"已校验离线 Windows 与启动目录，使用宿主 System32\\sfc.exe。";
    return r;
}
namespace {
// UI-only parser. It never classifies health or changes the tool result.
struct LiveProgress {
    Decoder decoder;
    std::vector<BYTE> probe;
    std::wstring line;
    bool ready = false, disabled = false;
    int last = -1;
    SfcProgress notify;
    explicit LiveProgress(SfcProgress p) : notify(std::move(p)) {}
    void Text(const std::wstring &s) {
        for (wchar_t c : s) {
            if (c == L'\r' || c == L'\n') {
                line.clear();
                continue;
            }
            if (c == L'\b') {
                if (!line.empty())
                    line.pop_back();
                continue;
            }
            line += c;
            if (line.size() > 1024) {
                line.clear();
                continue;
            }
            if (c != L'%')
                continue;
            size_t end = line.size() - 1, start = end;
            while (start && line[start - 1] >= L'0' && line[start - 1] <= L'9')
                --start;
            if (start == end || end - start > 3 || (start && line[start - 1] == L'.'))
                continue;
            std::wstring lower = line;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](wchar_t x) { return wchar_t(towlower(x)); });
            if (lower.find(L"verification") == lower.npos && lower.find(L"验证") == lower.npos)
                continue;
            int n = 0;
            for (size_t i = start; i < end; ++i)
                n = n * 10 + (line[i] - L'0');
            if (n > 100 || n == last)
                continue;
            last = n;
            if (notify)
                try {
                    notify(n, L"SFC 验证进度 " + std::to_wstring(n) + L"%");
                } catch (...) {
                }
        }
    }
    void Feed(const BYTE *b, size_t n, bool final = false) noexcept {
        try {
            if (disabled)
                return;
            if (!ready) {
                if (n)
                    probe.insert(probe.end(), b, b + n);
                if (probe.size() < 128 && !final)
                    return;
                size_t skip = 0;
                decoder.encoding = Detect(probe, skip);
                if (decoder.encoding == Encoding::Unknown) {
                    disabled = true;
                    return;
                }
                ready = true;
                Text(decoder.Feed(probe.data() + skip, probe.size() - skip, final));
                probe.clear();
            } else
                Text(decoder.Feed(b, n, final));
            if (decoder.bad)
                disabled = true;
        } catch (...) {
            disabled = true;
        }
    }
};
using RawWriter = bool (*)(HANDLE, const void *, size_t);
SfcResult RunCaptured(const SfcOptions &o, std::atomic_bool &stop, const SfcProgress &progress, SfcResult r,
                      const std::wstring &exe, std::wstring command, const std::wstring &win,
                      RawWriter writeRaw = WriteAll) {
    auto fail = [&](HRESULT hr, const std::wstring &s) {
        r.hr = hr;
        r.detail = s;
        r.stopRequested = r.stopRequested || stop.load();
        return r;
    };
    if (stop.load())
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"SFC 尚未启动，已停止后续阶段。");
    Handle raw(CreateFileW(r.rawLog.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!raw.valid())
        return fail(Error(), L"无法创建原始输出日志，未启动 SFC。");
    Report(progress, L"SFC 输出日志：" + r.rawLog);
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return fail(Error(), L"无法创建 SFC 输出管道。");
    Handle read(rd), write(wr);
    if (!SetHandleInformation(read.h, HANDLE_FLAG_INHERIT, 0))
        return fail(Error(), L"无法限制 SFC 管道继承。");
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!input.valid())
        return fail(Error(), L"无法创建 SFC 标准输入。");
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<BYTE> attributes(size);
    auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &size))
        return fail(Error(), L"无法初始化 SFC 句柄白名单。");
    struct AttrExit {
        LPPROC_THREAD_ATTRIBUTE_LIST p;
        ~AttrExit() {
            DeleteProcThreadAttributeList(p);
        }
    } attr{list};
    HANDLE inherited[] = {write.h, input.h};
    if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited),
                                   nullptr, nullptr))
        return fail(Error(), L"无法限定 SFC 继承句柄。");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.h;
    startup.StartupInfo.hStdOutput = write.h;
    startup.StartupInfo.hStdError = write.h;
    startup.lpAttributeList = list;
    PROCESS_INFORMATION pi{};
    std::wstring waitingStage = L"等待 SFC 自然退出",
                 stopMessage = L"已请求当前 SFC 阶段完成后停止；正在等待其自然退出。",
                 startedMessage = L"SFC 进程已启动；等待自然退出。";
    Report(progress, o.operation == SfcOperation::Verify ? L"启动系统文件只验证（SFC /verifyonly）"
                                                         : L"启动系统文件修复（SFC /scannow）");
    if (stop.load())
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"SFC 尚未启动，已停止后续阶段。");
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, win.c_str(),
                        &startup.StartupInfo, &pi))
        return fail(Error(), L"无法启动宿主 SFC；原始日志保留。");
    Handle process(pi.hProcess), thread(pi.hThread);
    struct NaturalExit {
        Handle &process;
        Handle &read;
        ~NaturalExit() {
            read.Close();
            WaitForSingleObject(process.h, INFINITE);
        }
    } natural{process, read};
    r.started = true;
    r.stage.swap(waitingStage);
    write.Close();
    input.Close();
    Report(progress, startedMessage);
    LiveProgress live(progress);
    HRESULT io = S_OK;
    bool pipeOpen = true, exitObserved = false, notified = false;
    std::array<BYTE, 32768> buffer{};
    // Drain even after log failure: a full output pipe must never deadlock SFC.
    for (;;) {
        if (stop.load()) {
            r.stopRequested = true;
            if (!notified) {
                Report(progress, stopMessage);
                notified = true;
            }
        }
        DWORD available = 0;
        if (pipeOpen) {
            if (!PeekNamedPipe(read.h, nullptr, 0, nullptr, &available, nullptr)) {
                DWORD e = GetLastError();
                if (e != ERROR_BROKEN_PIPE && io == S_OK)
                    io = Error(e);
                pipeOpen = false;
                read.Close();
            } else if (available) {
                DWORD got = 0;
                if (!ReadFile(read.h, buffer.data(), DWORD(std::min<size_t>(available, buffer.size())), &got,
                              nullptr)) {
                    DWORD e = GetLastError();
                    if (e != ERROR_BROKEN_PIPE && io == S_OK)
                        io = Error(e);
                    pipeOpen = false;
                    read.Close();
                } else if (got) {
                    live.Feed(buffer.data(), got);
                    if (!writeRaw(raw.h, buffer.data(), got) && io == S_OK)
                        io = Error();
                }
                continue;
            }
        }
        DWORD waited = WaitForSingleObject(process.h, available ? 0 : 25);
        if (waited == WAIT_OBJECT_0) {
            exitObserved = true;
            if (!pipeOpen)
                break;
            // The child may have written its terminal result while the wait was in
            // progress. Never decide EOF using the availability sampled before wait.
            DWORD remaining = 0;
            if (!PeekNamedPipe(read.h, nullptr, 0, nullptr, &remaining, nullptr)) {
                DWORD e = GetLastError();
                if (e != ERROR_BROKEN_PIPE && io == S_OK)
                    io = Error(e);
                pipeOpen = false;
                read.Close();
                break;
            }
            if (!remaining)
                break;
        } else if (waited == WAIT_FAILED) {
            if (io == S_OK)
                io = Error();
            break;
        }
    }
    // No termination mechanism is installed. Even an observation/log error must
    // keep this owner alive until the child has returned naturally.
    if (!exitObserved) {
        read.Close();
        DWORD w = WaitForSingleObject(process.h, INFINITE);
        exitObserved = w == WAIT_OBJECT_0;
        if (!exitObserved && io == S_OK)
            io = Error();
    }
    r.processExited = exitObserved;
    if (exitObserved && !GetExitCodeProcess(process.h, &r.exitCode) && io == S_OK)
        io = Error();
    r.stopRequested = r.stopRequested || stop.load();
    read.Close();
    if (!FlushFileBuffers(raw.h) && io == S_OK)
        io = Error();
    r.stage = L"核对 SFC 终端结果";
    live.Feed(nullptr, 0, true);
    HRESULT decoded = DecodeLog(raw.h, r.textLog, r.report);
    if (io == S_OK && decoded != S_OK)
        io = decoded;
    raw.Close();
    if (!o.online) {
        Handle off(CreateFileW(r.offLog.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        LARGE_INTEGER length{};
        if (!off.valid() || !GetFileSizeEx(off.h, &length) || !length.QuadPart) {
            if (io == S_OK)
                io = off.valid() ? HRESULT_FROM_WIN32(ERROR_HANDLE_EOF) : Error();
        }
    }
    if (io != S_OK)
        return fail(io, L"SFC 已结束，但输出或日志保存/解码不完整；不能据此确认成功。" +
                            SfcReportText(r.report) + L"。");
    if (!r.processExited)
        return fail(E_FAIL, L"未能确认 SFC 已自然退出。");
    if (r.exitCode != 0)
        return fail(HRESULT_FROM_WIN32(ERROR_PROCESS_ABORTED),
                    L"SFC 返回非零退出码；保留原始退出码与终端报告分别核对。" + SfcReportText(r.report) +
                        L"。");
    if (o.operation == SfcOperation::Verify && r.report == SfcReport::Repaired) {
        r.report = SfcReport::Unknown;
        return fail(E_UNEXPECTED, L"只验证操作意外报告了已修复；不能确认本次结果，请核对原始日志。");
    }
    r.hr = Outcome(r.report);
    r.detail = SfcReportText(r.report) + L"。退出码 0 本身不代表健康。";
    if (r.stopRequested)
        r.detail += L" 已请求阶段完成后停止，未向 SFC 发送中断。";
    return r;
}
} // namespace
SfcResult RunSfc(const SfcOptions &o, std::atomic_bool &stop, const SfcProgress &progress) {
    SfcResult r;
    r.stage = L"启动 SFC";
    auto fail = [&](HRESULT hr, const std::wstring &s) {
        r.hr = hr;
        r.detail = s;
        r.stopRequested = stop.load();
        return r;
    };
    if (stop.load())
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"SFC 尚未启动，已停止后续阶段。");
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"))
        return fail(E_NOTIMPL, L"Wine 不执行真实 SFC 维护。");
    MaintenanceLock operationLock;
    if (operationLock.Result() != S_OK)
        return fail(operationLock.Result(),
                    L"已有 ADism 维护任务，或上次任务异常退出；未启动新的维护。请先核对系统状态。 ");
    r = ValidateSfcTarget(o);
    if (r.hr != S_OK) {
        r.stopRequested = stop.load();
        return r;
    }
    Handle directory;
    HRESULT hr = OwnLogs(r, directory);
    if (hr != S_OK)
        return fail(hr, L"无法创建本进程拥有的 SFC 日志目录。");
    if (o.online)
        r.offLog.clear();
    wchar_t sys[32768]{}, win[32768]{};
    UINT sn = GetSystemDirectoryW(sys, 32768), wn = GetWindowsDirectoryW(win, 32768);
    if (!sn || sn >= 32768 || !wn || wn >= 32768)
        return fail(Error(), L"无法定位宿主 SFC。");
    const auto exe = Join(sys, L"sfc.exe");
    return RunCaptured(o, stop, progress, r, exe, Command(exe, o, r.offLog), win);
}

int SfcSelfTest() {
    int fails = 0;
    auto check = [&](bool v) {
        if (!v)
            ++fails;
    };
    check(Root(L"g:") == L"G:\\");
    check(Root(L"G:\\Windows").empty() && Root(L"\\\\server\\share").empty() && Root(L"G:\\.").empty());
    {
        std::vector<int> seen;
        LiveProgress p([&](int n, const std::wstring &) { seen.push_back(n); });
        const std::wstring text = L"Verification 4%\b\b17% complete.\r\n验证 100% 已完成。\r\nrandom file "
                                  L"75%\r\nVerification 101%\r\nVerification 1.5%";
        std::vector<BYTE> bytes{0xff, 0xfe};
        for (auto c : text) {
            bytes.push_back(BYTE(c));
            bytes.push_back(BYTE(c >> 8));
        }
        for (auto b : bytes)
            p.Feed(&b, 1);
        p.Feed(nullptr, 0, true);
        check(seen == std::vector<int>({4, 17, 100}));
    }
    {
        std::vector<int> seen;
        LiveProgress p([&](int n, const std::wstring &) { seen.push_back(n); });
        const std::string text = "Verification 28% complete.\n";
        for (auto c : text) {
            BYTE b = BYTE(c);
            p.Feed(&b, 1);
        }
        p.Feed(nullptr, 0, true);
        check(seen == std::vector<int>({28}));
    }
    const std::pair<std::wstring, SfcReport> cases[] = {
        {L"Windows Resource Protection did not find any integrity violations.\r\n", SfcReport::Clean},
        {L"Windows 资源保护找到了完整性违规。", SfcReport::Unrepaired},
        {L"Windows 资源保护找到了损坏文件并成功修复了它们。", SfcReport::Repaired},
        {L"Windows Resource Protection could not perform the requested operation.", SfcReport::Unable},
        {L"Verification 100% complete.\r\n[SR] Repairing corrupted file x", SfcReport::Unknown},
        {L"Windows Resource Protection found corrupt files but was unable to fix some of them.",
         SfcReport::Unrepaired}};
    for (const auto &c : cases) {
        Classifier p;
        for (auto x : c.first)
            p.Feed(std::wstring(1, x));
        check(p.Finish() == c.second);
    }
    {
        Classifier p;
        p.Feed(cases[0].first + L"\n" + cases[1].first);
        check(p.Finish() == SfcReport::Unknown);
    }
    for (const auto &c : cases) {
        std::vector<BYTE> bytes;
        for (wchar_t x : c.first) {
            bytes.push_back(BYTE(x & 255));
            bytes.push_back(BYTE(x >> 8));
        }
        size_t skip = 0;
        auto enc = Detect(bytes, skip);
        check(enc == Encoding::Le);
        Decoder d;
        d.encoding = enc;
        Classifier p;
        for (auto x : bytes)
            p.Feed(d.Feed(&x, 1, false));
        p.Feed(d.Feed(nullptr, 0, true));
        check(!d.bad && p.Finish() == c.second);
    }
    {
        Decoder d;
        d.encoding = Encoding::Utf8;
        const BYTE a[] = {0xe4, 0xb8, 0xad};
        std::wstring out;
        for (auto b : a)
            out += d.Feed(&b, 1, false);
        out += d.Feed(nullptr, 0, true);
        check(!d.bad && out == L"中");
    }
    {
        Decoder d;
        d.encoding = Encoding::Le;
        BYTE b = 0x41;
        d.Feed(&b, 1, true);
        check(d.bad);
    }
    {
        const std::vector<std::wstring> args = {L"", L"C:\\Path With Space\\", L"a\"b\\",
                                                L"/offlogfile=C:\\My Logs\\sfc.log"};
        std::wstring command = L"test";
        for (auto &a : args)
            command += L" " + Quote(a);
        int n = 0;
        LPWSTR *parsed = CommandLineToArgvW(command.c_str(), &n);
        check(parsed && n == int(args.size()) + 1);
        if (parsed) {
            for (int i = 1; i < n; ++i)
                check(parsed[i] == args[size_t(i - 1)]);
            LocalFree(parsed);
        }
    }
    {
        std::atomic_bool stop{true};
        auto r = RunSfc({}, stop, {});
        check(r.hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) && !r.started && !r.processExited &&
              r.stopRequested);
    }
    {
        VARIANT v;
        VariantInit(&v);
        DWORD d = 0;
        v.vt = VT_I4;
        v.lVal = -1;
        check(!UInt(v, d));
        v.vt = VT_NULL;
        check(!UInt(v, d));
        v.vt = VT_UI4;
        v.ulVal = DWORD(-1);
        check(!UInt(v, d));
    }
    check(Outcome(SfcReport::Unknown) != S_OK && Outcome(SfcReport::Unrepaired) != S_OK &&
          Outcome(SfcReport::Unable) != S_OK && Outcome(SfcReport::Clean) == S_OK);
    return fails;
}
} // namespace servicing
