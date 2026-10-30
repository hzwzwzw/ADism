// SPDX-License-Identifier: GPL-3.0-only
#include "cbs_backend.h"
#include "wim_backend.h"
#include "cbs_source_mount.h"
#include "safety.h"
#include <objbase.h>
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <mutex>
#include <vector>
#include <sstream>
#include <cstring>

namespace servicing {
namespace {
// GUIDs and slots recovered from CBSHost.dll 10.1.1002.1, x64.
const GUID kSessionClass = {0x752073a1, 0x23f2, 0x4396, {0x85, 0xf0, 0x8f, 0xdb, 0x87, 0x9e, 0xd0, 0xed}};
const GUID kSession = {0x75207391, 0x23f2, 0x4396, {0x85, 0xf0, 0x8f, 0xdb, 0x87, 0x9e, 0xd0, 0xed}};
const GUID kUi = {0x75207392, 0x23f2, 0x4396, {0x85, 0xf0, 0x8f, 0xdb, 0x87, 0x9e, 0xd0, 0xed}};
const GUID kSession8 = {0xf568c899, 0xaf4f, 0x4eaa, {0xb1, 0x2a, 0xb8, 0xe5, 0xf1, 0xb2, 0x19, 0xde}};
const GUID kFullSession9 = {0x9c7e3cf3, 0x4c97, 0x4d36, {0xbd, 0xeb, 0xe3, 0x09, 0x3c, 0x22, 0x8c, 0x22}};
const GUID kExecutor = {0xdc95a094, 0xee0e, 0x4974, {0x96, 0x00, 0x02, 0x7d, 0x23, 0x21, 0xc2, 0xd4}};
constexpr HRESULT kCancelled = HRESULT_FROM_WIN32(ERROR_CANCELLED);
using InitSessionFn = HRESULT(WINAPI *)(IUnknown *, ULONG, LPCWSTR, LPCWSTR, LPCWSTR);
using CreateSessionFn = HRESULT(WINAPI *)(IUnknown *, ULONG, const GUID *, IUnknown **);
using RegisterUiFn = HRESULT(WINAPI *)(IUnknown *, IUnknown *);
using ExecuteFn = HRESULT(WINAPI *)(IUnknown *, ULONG, ULONG *);
using EnhancedOptionsFn = HRESULT(WINAPI *)(IUnknown *, ULONG);
using AddSourceFn = HRESULT(WINAPI *)(IUnknown *, ULONG, LPCWSTR);
using PropertyFn = HRESULT(WINAPI *)(IUnknown *, ULONG, LPCWSTR *);
template <class F> F Slot(IUnknown *object, size_t index) {
    return reinterpret_cast<F>((*reinterpret_cast<void ***>(object))[index]);
}
struct Ref {
    IUnknown *p = nullptr;
    Ref() = default;
    Ref(const Ref &) = delete;
    Ref &operator=(const Ref &) = delete;
    ~Ref() {
        reset();
    }
    void reset() {
        if (p) {
            auto *q = p;
            p = nullptr;
            q->Release();
        }
    }
    IUnknown **put() {
        reset();
        return &p;
    }
};
void Report(const CbsProgress &fn, int value, const std::wstring &text) {
    if (fn) {
        try {
            fn(value, text);
        } catch (...) {
        }
    }
}
std::wstring Join(const std::wstring &a, const std::wstring &b) {
    if (a.empty())
        return b;
    return a + (a.back() == L'\\' ? L"" : L"\\") + b;
}
bool StartsI(const std::wstring &value, const std::wstring &prefix) {
    return value.size() >= prefix.size() && _wcsnicmp(value.c_str(), prefix.c_str(), prefix.size()) == 0;
}
bool Exists(const std::wstring &p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}
HRESULT WinError(DWORD e = GetLastError()) {
    return HRESULT_FROM_WIN32(e ? e : ERROR_GEN_FAILURE);
}
std::wstring Hex(HRESULT hr) {
    wchar_t b[20];
    swprintf(b, 20, L"0x%08lX", static_cast<unsigned long>(hr));
    return b;
}
std::wstring Canonical(const std::wstring &path) {
    if (path.empty() || StartsI(path, L"\\\\?\\UNC\\"))
        return {};
    const std::wstring absoluteInput = (path.size() == 2 && path[1] == L':') ? path + L"\\" : path;
    DWORD n = GetFullPathNameW(absoluteInput.c_str(), 0, nullptr, nullptr);
    if (!n)
        return {};
    std::vector<wchar_t> b(n + 1);
    if (!GetFullPathNameW(absoluteInput.c_str(), static_cast<DWORD>(b.size()), b.data(), nullptr))
        return {};
    std::wstring p = b.data();
    if (StartsI(p, L"\\\\?\\"))
        p.erase(0, 4);
    DWORD ln = GetLongPathNameW(p.c_str(), nullptr, 0);
    if (ln) {
        std::vector<wchar_t> l(ln + 1);
        if (GetLongPathNameW(p.c_str(), l.data(), static_cast<DWORD>(l.size())))
            p = l.data();
    }
    while (!p.empty() && p.back() == L'\\')
        p.pop_back();
    return p;
}
bool IsX64Image(const std::wstring &path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return false;
    IMAGE_DOS_HEADER dos{};
    DWORD n = 0;
    bool good = false;
    if (ReadFile(f, &dos, sizeof(dos), &n, nullptr) && n == sizeof(dos) &&
        dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0) {
        LARGE_INTEGER at{};
        at.QuadPart = dos.e_lfanew;
        DWORD signature = 0;
        IMAGE_FILE_HEADER coff{};
        good = SetFilePointerEx(f, at, nullptr, FILE_BEGIN) && ReadFile(f, &signature, 4, &n, nullptr) &&
               n == 4 && signature == IMAGE_NT_SIGNATURE && ReadFile(f, &coff, sizeof(coff), &n, nullptr) &&
               n == sizeof(coff) && coff.Machine == IMAGE_FILE_MACHINE_AMD64;
    }
    CloseHandle(f);
    return good;
}
HRESULT TargetVersion(const std::wstring &ntdll, DWORD &major, DWORD &minor) {
    DWORD ignored = 0, size = GetFileVersionInfoSizeW(ntdll.c_str(), &ignored);
    if (!size)
        return WinError();
    std::vector<BYTE> bytes(size);
    if (!GetFileVersionInfoW(ntdll.c_str(), 0, size, bytes.data()))
        return WinError();
    VS_FIXEDFILEINFO *fixed = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void **>(&fixed), &length) ||
        length < sizeof(*fixed) || fixed->dwSignature != 0xfeef04bd)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    major = HIWORD(fixed->dwFileVersionMS);
    minor = LOWORD(fixed->dwFileVersionMS);
    return S_OK;
}
bool VersionSupported(DWORD major, DWORD minor) {
    return major > 6 || (major == 6 && minor >= 2);
}
HRESULT InitializeSession(IUnknown *session, LPCWSTR root, LPCWSTR windows) {
    return session ? Slot<InitSessionFn>(session, 3)(session, 0, L"ADism", root, windows) : E_POINTER;
}
bool SameFile(const std::wstring &a, const std::wstring &b) {
    HANDLE fa = CreateFileW(a.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, 0, nullptr);
    HANDLE fb = CreateFileW(b.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, 0, nullptr);
    BY_HANDLE_FILE_INFORMATION ia{}, ib{};
    bool equal = fa != INVALID_HANDLE_VALUE && fb != INVALID_HANDLE_VALUE &&
                 GetFileInformationByHandle(fa, &ia) && GetFileInformationByHandle(fb, &ib) &&
                 ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber &&
                 ia.nFileIndexHigh == ib.nFileIndexHigh && ia.nFileIndexLow == ib.nFileIndexLow;
    if (fa != INVALID_HANDLE_VALUE)
        CloseHandle(fa);
    if (fb != INVALID_HANDLE_VALUE)
        CloseHandle(fb);
    return equal;
}

// CBS registers a proxy/stub for kUi. The original callback supports only
// IUnknown and kUi; no IMarshal/free-threaded-marshaler was found in its QI.
// Unused slots return S_OK regardless of their arguments, as in the x64 sample.
struct UiAbi : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Ignored3() = 0;
    virtual HRESULT STDMETHODCALLTYPE Ignored4() = 0;
    virtual HRESULT STDMETHODCALLTYPE Ignored5() = 0;
    virtual HRESULT STDMETHODCALLTYPE QueryAction(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG,
                                                  ULONGLONG *) = 0;
    virtual HRESULT STDMETHODCALLTYPE Progress(ULONG, ULONG, ULONG, ULONGLONG *) = 0;
};
class Ui final : public UiAbi {
    LONG refs_ = 1;
    std::atomic_bool &cancel_;
    CbsProgress progress_;
    std::mutex mutex_;

  public:
    Ui(std::atomic_bool &c, CbsProgress p) : cancel_(c), progress_(std::move(p)) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (!IsEqualGUID(iid, IID_IUnknown) && !IsEqualGUID(iid, kUi))
            return E_NOINTERFACE;
        *out = static_cast<UiAbi *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&refs_));
    }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG n = InterlockedDecrement(&refs_);
        if (!n)
            delete this;
        return static_cast<ULONG>(n);
    }
    HRESULT STDMETHODCALLTYPE Ignored3() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Ignored4() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Ignored5() override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE QueryAction(ULONGLONG, ULONGLONG, ULONGLONG, ULONGLONG,
                                          ULONGLONG *action) override {
        if (cancel_.load() && action)
            *action = 2;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Progress(ULONG, ULONG current, ULONG total, ULONGLONG *action) override {
        if (total && current <= total) {
            std::lock_guard<std::mutex> lock(mutex_);
            Report(progress_, static_cast<int>((static_cast<uint64_t>(current) * 100) / total),
                   L"CBS 正在处理组件存储");
        }
        if (cancel_.load() && action)
            *action = 2;
        return S_OK;
    }
};

// Takes ownership of initialSession, including all failure paths. In-memory
// fake interfaces exercise this same function; they never open Windows CBS.
CbsResult Drive(IUnknown *initialSession, CbsOperation operation, std::atomic_bool &cancel,
                const CbsProgress &progress, const std::wstring &source = {}, bool fullPayloadCheck = false,
                RepairSourceKind sourceKind = RepairSourceKind::Default) {
    CbsResult result;
    Ref base;
    base.p = initialSession;
    Ref session8, exec, ui;
    auto done = [&](HRESULT hr, const wchar_t *stage) {
        result.hr = hr;
        result.stage = stage;
        result.cancelRequested = cancel.load();
        if (result.cancelRequested || hr == kCancelled) {
            result.imageStateUnknown = true;
            result.health = -1;
            if (hr == S_OK)
                result.hr = kCancelled;
        }
        return result;
    };
    if (!base.p)
        return done(E_POINTER, L"创建 CBS 会话");
    if (cancel.load())
        return done(kCancelled, L"开始前取消");
    HRESULT hr = base.p->QueryInterface(kSession8, reinterpret_cast<void **>(session8.put()));
    if (hr != S_OK || !session8.p)
        return done(hr == S_OK ? E_NOINTERFACE : hr, L"查询 CBS 健康接口");
    if (fullPayloadCheck) {
        // Session9 is explicitly queried: its 24-method Windows proxy exposes
        // SetEnhancedOptions at slot23 for both online and offline sessions.
        // Never call it through the shorter Session8 or an unmarshalable IID.
        Ref fullSession;
        hr = base.p->QueryInterface(kFullSession9, reinterpret_cast<void **>(fullSession.put()));
        if (hr != S_OK || !fullSession.p) {
            result.detail = L"当前维护堆栈不支持完整负载校验接口。关闭完整校验可选择自动兼容路径。";
            return done(FAILED(hr) ? hr : E_NOINTERFACE, L"查询 CBS 完整校验接口");
        }
        hr = Slot<EnhancedOptionsFn>(fullSession.p, 23)(fullSession.p,
                                                        operation == CbsOperation::Scan ? 0x800u : 0x1000u);
        if (hr != S_OK) {
            result.detail = L"CBS 未接受完整负载校验请求，原始状态：" + Hex(hr);
            return done(FAILED(hr) ? hr : E_UNEXPECTED, L"设置完整负载校验");
        }
        Report(progress, -1, L"已请求 CBS 手动维护模式，完整校验组件负载");
    } else
        Report(progress, -1, L"CBS 自动维护模式，可能跳过组件负载内容校验");
    if (operation == CbsOperation::Restore && !source.empty()) {
        Report(progress, -1, L"向 CBS 添加修复来源：" + source);
        hr = Slot<AddSourceFn>(session8.p, 15)(session8.p, 0, source.c_str());
        if (hr != S_OK) {
            result.detail = L"CBS 添加来源返回 " + Hex(hr) + L"；未确认所选来源已注册，尚未执行修复。";
            // S_FALSE here can mean CBS skipped a source (raw WIM offline).
            // It is not partial repair: Execute has not been entered.
            return done(FAILED(hr) ? hr : E_UNEXPECTED, L"添加 CBS 修复来源");
        }
    }
    ui.p = new Ui(cancel, progress);
    hr = Slot<RegisterUiFn>(session8.p, 16)(session8.p, ui.p);
    if (hr != S_OK)
        return done(hr, L"注册 CBS 回调");
    hr = base.p->QueryInterface(kExecutor, reinterpret_cast<void **>(exec.put()));
    if (hr != S_OK || !exec.p)
        return done(hr == S_OK ? E_NOINTERFACE : hr, L"查询 CBS 执行接口");
    // Match helper's release-before-execute ordering; session8 retains the
    // view needed to read final health properties after the execute call.
    base.reset();
    ULONG opaque = 0;
    Report(progress, -1, operation == CbsOperation::Scan ? L"正在验证受损" : L"正在修复受损");
    // These are CBS FinalizeEx bits, not the different DISM provider option bits.
    ULONG flags = fullPayloadCheck ? 0u : (operation == CbsOperation::Scan ? 0x4100u : 0x8100u);
    if (sourceKind == RepairSourceKind::WindowsUpdate)
        flags |= 0x40000u;
    else if (sourceKind == RepairSourceKind::LocalOnly)
        flags |= 0x20000u;
    Report(progress, -1,
           L"CBS 执行参数：" + Hex(HRESULT(flags)) +
               (sourceKind == RepairSourceKind::WindowsUpdate ? L"；明确请求 Windows Update"
                : sourceKind == RepairSourceKind::LocalOnly   ? L"；禁止 Windows Update"
                                                              : L"；使用自动来源策略"));
    hr = Slot<ExecuteFn>(exec.p, 14)(exec.p, flags, &opaque);
    result.requiredAction = opaque;
    result.requiredActionAvailable = hr == S_OK;
    if (hr == S_OK)
        Report(progress, -1, L"CBS 所需动作（原始值）：" + std::to_wstring(opaque));
    exec.reset();
    if (hr == static_cast<HRESULT>(0x800f0820u))
        hr = kCancelled;
    if (hr != S_OK) {
        result.imageStateUnknown = true;
        if (sourceKind == RepairSourceKind::WindowsUpdate) {
            switch (ULONG(hr)) {
            case 0x800f0906u:
                result.detail =
                    L"Windows Update 修复内容下载失败。请查看 CBS 日志中的代理、网络和更新服务错误。";
                break;
            case 0x800f0907u:
                result.detail = L"系统策略禁止下载修复内容。ADism "
                                L"不会覆盖管理员设置；可按策略配置来源或选择匹配的本地映像。";
                break;
            case 0x800f0950u:
            case 0x800f0915u:
            case 0x800f081fu:
                result.detail = L"Windows Update 模式下未能取得本次所需的完整匹配修复内容。请核对 CBS "
                                L"原始日志，也可选择匹配的 WIM/Windows 目录。";
                break;
            default:
                result.detail = L"Windows Update 修复请求未完成，原始错误：" + Hex(hr) +
                                L"。请查看 CBS 日志；不会自动改用未指定的外部映像。";
                break;
            }
        }
        return done(hr, L"执行 CBS 操作");
    }
    if (operation == CbsOperation::Scan) {
        LPCWSTR text = nullptr;
        hr = Slot<PropertyFn>(session8.p, 12)(session8.p, 6, &text);
        if (hr != S_OK || !text)
            return done(hr == S_OK ? E_POINTER : hr, L"读取受损状态");
        if (wcscmp(text, L"0") && wcscmp(text, L"1"))
            return done(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), L"受损状态字段无效");
        if (text[0] != L'1')
            result.health = 0;
        else {
            text = nullptr;
            hr = Slot<PropertyFn>(session8.p, 12)(session8.p, 3, &text);
            if (hr != S_OK || !text)
                return done(hr == S_OK ? E_POINTER : hr, L"读取可修复状态");
            if (wcscmp(text, L"0") && wcscmp(text, L"1"))
                return done(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), L"可修复状态字段无效");
            result.health = text[0] == L'1' ? 2 : 1;
        }
    }
    // Do not free property strings: the original does not establish ownership.
    session8.reset();
    ui.reset();
    return done(S_OK, L"完成");
}

HRESULT InitSecurity() {
    std::array<BYTE, SECURITY_MAX_SID_SIZE> system{}, admins{}, backup{};
    DWORD ns = static_cast<DWORD>(system.size()), na = static_cast<DWORD>(admins.size()),
          nb = static_cast<DWORD>(backup.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &ns) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins.data(), &na) ||
        !CreateWellKnownSid(WinBuiltinBackupOperatorsSid, nullptr, backup.data(), &nb))
        return WinError();
    std::array<EXPLICIT_ACCESSW, 3> entries{};
    PSID sids[] = {backup.data(), admins.data(), system.data()};
    for (size_t i = 0; i < entries.size(); ++i) {
        entries[i].grfAccessPermissions = 0xb;
        entries[i].grfAccessMode = SET_ACCESS;
        entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        entries[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
    }
    PACL acl = nullptr;
    DWORD e = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl);
    if (e)
        return WinError(e);
    SECURITY_DESCRIPTOR sd{};
    bool ok = InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
              SetSecurityDescriptorOwner(&sd, system.data(), FALSE) &&
              SetSecurityDescriptorGroup(&sd, admins.data(), FALSE) &&
              SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE);
    HRESULT hr = ok ? CoInitializeSecurity(&sd, -1, nullptr, nullptr, 3, 3, nullptr, 0, nullptr) : WinError();
    LocalFree(acl);
    return hr;
}
HRESULT EnablePrivilege(LPCWSTR name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
        return WinError();
    TOKEN_PRIVILEGES p{};
    p.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &p.Privileges[0].Luid)) {
        HRESULT hr = WinError();
        CloseHandle(token);
        return hr;
    }
    p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &p, 0, nullptr, nullptr);
    DWORD e = GetLastError();
    CloseHandle(token);
    return ok && e == ERROR_SUCCESS ? S_OK : WinError(e);
}
struct Hive {
    std::wstring name;
    HKEY key = nullptr;
    bool owns = false;
    HRESULT Load(const std::wstring &file, const std::wstring &n) {
        name = n;
        DWORD e = RegLoadKeyW(HKEY_LOCAL_MACHINE, name.c_str(), file.c_str());
        if (e)
            return WinError(e);
        owns = true;
        e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key);
        return e ? WinError(e) : S_OK;
    }
    HRESULT Close() {
        if (key) {
            RegCloseKey(key);
            key = nullptr;
        }
        if (owns) {
            DWORD e = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, name.c_str());
            if (e)
                return WinError(e);
            owns = false;
        }
        return S_OK;
    }
    ~Hive() {
        Close();
    }
};
std::wstring ExpandTarget(const std::wstring &value, const std::wstring &root) {
    if (StartsI(value, L"%SystemDrive%"))
        return root + value.substr(13);
    if (StartsI(value, L"%SystemRoot%"))
        return Join(root, L"Windows") + value.substr(12);
    if (StartsI(value, L"%windir%"))
        return Join(root, L"Windows") + value.substr(8);
    return {};
}
HRESULT StackFromSoftware(HKEY software, const std::wstring &root, std::wstring &stack) {
    HKEY key = nullptr;
    DWORD e =
        RegOpenKeyExW(software, L"Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Version", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key);
    if (e)
        return WinError(e);
    DWORD names = 0, data = 0;
    e = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &names, &data,
                         nullptr, nullptr);
    if (e || names > 32767 || data > 65536) {
        RegCloseKey(key);
        return e ? WinError(e) : HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    std::vector<wchar_t> name(names + 2), value(data / sizeof(wchar_t) + 2);
    for (DWORD index = 0;; ++index) {
        DWORD nc = static_cast<DWORD>(name.size()),
              cb = static_cast<DWORD>((value.size() - 1) * sizeof(wchar_t)), type = 0;
        e = RegEnumValueW(key, index, name.data(), &nc, nullptr, &type,
                          reinterpret_cast<BYTE *>(value.data()), &cb);
        if (e == ERROR_NO_MORE_ITEMS)
            break;
        if (e)
            break;
        if (nc && (type == REG_SZ || type == REG_EXPAND_SZ) && cb % sizeof(wchar_t) == 0) {
            value[cb / sizeof(wchar_t)] = 0;
            stack = ExpandTarget(value.data(), root);
            break;
        }
    }
    RegCloseKey(key);
    if (stack.empty())
        return e && e != ERROR_NO_MORE_ITEMS ? WinError(e) : HRESULT_FROM_WIN32(ERROR_BAD_ENVIRONMENT);
    stack = Canonical(stack);
    std::wstring prefix = Join(root, L"Windows\\WinSxS") + L"\\";
    if (!StartsI(stack + L"\\", prefix))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    return Exists(Join(stack, L"CbsCore.dll")) ? S_OK : HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

// Sources remain borrowed for Execute. Online WIM is passed to CBS; an offline
// source may use an owned read-only mount with explicit cleanup.
struct Profile {
    DWORD major = 0, minor = 0, build = 0, revision = 0;
    std::wstring edition, type;
    std::vector<std::wstring> languages;
};
struct Key {
    HKEY h = nullptr;
    ~Key() {
        if (h)
            RegCloseKey(h);
    }
};
std::wstring RegText(HKEY key, const wchar_t *path, const wchar_t *name) {
    DWORD size = 0;
    if (RegGetValueW(key, path, name, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS || !size ||
        size > 65536)
        return {};
    std::vector<wchar_t> text(size / sizeof(wchar_t) + 1);
    if (RegGetValueW(key, path, name, RRF_RT_REG_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
        return {};
    return text.data();
}
HRESULT ReadProfileData(HKEY software, HKEY system, Profile &p) {
    constexpr auto version = L"Microsoft\\Windows NT\\CurrentVersion";
    auto build = RegText(software, version, L"CurrentBuildNumber");
    try {
        size_t end = 0;
        p.build = std::stoul(build, &end);
        if (end != build.size())
            return E_INVALIDARG;
    } catch (...) {
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    DWORD bytes = sizeof(p.revision);
    DWORD e = RegGetValueW(software, version, L"UBR", RRF_RT_REG_DWORD, nullptr, &p.revision, &bytes);
    if (e)
        return WinError(e);
    p.edition = RegText(software, version, L"EditionID");
    p.type = RegText(software, version, L"InstallationType");
    DWORD current = 0;
    bytes = sizeof(current);
    e = RegGetValueW(system, L"Select", L"Current", RRF_RT_REG_DWORD, nullptr, &current, &bytes);
    if (e || current > 999)
        return WinError(e ? e : ERROR_INVALID_DATA);
    wchar_t path[100];
    swprintf(path, 100, L"ControlSet%03lu\\Control\\MUI\\UILanguages", static_cast<unsigned long>(current));
    Key languages;
    e = RegOpenKeyExW(system, path, 0, KEY_READ, &languages.h);
    if (e)
        return WinError(e);
    for (DWORD i = 0;; ++i) {
        wchar_t name[256];
        DWORD n = 256;
        e = RegEnumKeyExW(languages.h, i, name, &n, nullptr, nullptr, nullptr, nullptr);
        if (e == ERROR_NO_MORE_ITEMS)
            break;
        if (e)
            return WinError(e);
        p.languages.emplace_back(name, n);
    }
    return !p.build || p.edition.empty() || p.type.empty() || p.languages.empty()
               ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA)
               : S_OK;
}

struct MetadataCopy {
    std::wstring path;
    HRESULT Create(const std::wstring &windows) {
        wchar_t temp[32768];
        DWORD n = GetTempPathW(32768, temp);
        if (!n || n >= 32768)
            return WinError();
        GUID id{};
        HRESULT hr = CoCreateGuid(&id);
        if (hr != S_OK)
            return hr;
        wchar_t text[40];
        StringFromGUID2(id, text, 40);
        std::wstring candidate = Join(temp, L"ADism-Metadata-" + std::wstring(text));
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                                  SDDL_REVISION_1, &descriptor, nullptr))
            return WinError();
        SECURITY_ATTRIBUTES sa = {sizeof(sa), descriptor, FALSE};
        BOOL made = CreateDirectoryW(candidate.c_str(), &sa);
        DWORD error = GetLastError();
        LocalFree(descriptor);
        if (!made)
            return WinError(error);
        path = candidate;
        for (auto name :
             {L"SOFTWARE", L"SOFTWARE.LOG1", L"SOFTWARE.LOG2", L"SYSTEM", L"SYSTEM.LOG1", L"SYSTEM.LOG2"}) {
            auto source = Join(windows, L"System32\\config\\" + std::wstring(name));
            DWORD attrs = GetFileAttributesW(source.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                DWORD e = GetLastError();
                if ((e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) && wcsstr(name, L".LOG"))
                    continue;
                return WinError(e);
            }
            if (!CopyFileW(source.c_str(), Join(path, name).c_str(), TRUE))
                return WinError();
            // Source attributes can be readonly (for example a mounted WIM).
            // Only the independent owned copy is made writable for hive replay.
            if (!SetFileAttributesW(Join(path, name).c_str(), FILE_ATTRIBUTE_NORMAL))
                return WinError();
        }
        return S_OK;
    }
    HRESULT Close() {
        if (path.empty())
            return S_OK;
        HRESULT hr = S_OK;
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW(Join(path, L"*").c_str(), &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
                    continue;
                if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    hr = HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
                    continue;
                }
                if (!DeleteFileW(Join(path, data.cFileName).c_str()))
                    hr = WinError();
            } while (FindNextFileW(find, &data));
            FindClose(find);
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND)
            hr = WinError();
        if (!RemoveDirectoryW(path.c_str()))
            hr = WinError();
        else
            path.clear();
        return hr;
    }
    ~MetadataCopy() {
        Close();
    }
};
HRESULT ReadProfile(const std::wstring &windows, bool live, Profile &p, const CbsProgress &progress) {
    const auto ntdll = Join(windows, L"System32\\ntdll.dll");
    if (!IsX64Image(ntdll))
        return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
    HRESULT hr = TargetVersion(ntdll, p.major, p.minor);
    if (hr != S_OK)
        return hr;
    if (live) {
        Key software, system;
        DWORD e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ | KEY_WOW64_64KEY, &software.h);
        if (e)
            return WinError(e);
        e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ | KEY_WOW64_64KEY, &system.h);
        if (e)
            return WinError(e);
        return ReadProfileData(software.h, system.h, p);
    }
    // A borrowed readonly mount must remain readonly. Snapshot metadata and
    // transaction logs, then let normal registry recovery operate on our copies.
    MetadataCopy copy;
    hr = copy.Create(windows);
    Hive software, system;
    if (hr == S_OK) {
        GUID id{};
        hr = CoCreateGuid(&id);
        if (hr == S_OK) {
            wchar_t idText[40];
            StringFromGUID2(id, idText, 40);
            auto prefix = L"ReaServicing_Source_" + std::to_wstring(GetCurrentProcessId()) + L"_" + idText;
            hr = software.Load(Join(copy.path, L"SOFTWARE"), prefix + L"_SOFTWARE");
            if (hr == S_OK)
                hr = system.Load(Join(copy.path, L"SYSTEM"), prefix + L"_SYSTEM");
            if (hr == S_OK)
                hr = ReadProfileData(software.key, system.key, p);
        }
    }
    HRESULT a = system.Close(), b = software.Close();
    if (a != S_OK || b != S_OK) {
        Report(progress, -1, L"元数据 hive 未能卸载；保留独立副本供检查：" + copy.path);
        copy.path.clear();
        return a != S_OK ? a : b;
    }
    HRESULT cleanup = copy.Close();
    if (cleanup != S_OK) {
        Report(progress, -1, L"元数据临时副本清理失败：" + copy.path);
        return cleanup;
    }
    return hr;
}

std::wstring ProfileText(const Profile &p) {
    std::wstring text = std::to_wstring(p.major) + L"." + std::to_wstring(p.minor) + L"." +
                        std::to_wstring(p.build) + L"." + std::to_wstring(p.revision) + L" x64 " + p.edition +
                        L" " + p.type + L" [";
    for (size_t i = 0; i < p.languages.size(); ++i) {
        if (i)
            text += L", ";
        text += p.languages[i];
    }
    return text + L"]";
}
bool EqualI(const std::wstring &a, const std::wstring &b) {
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}
HRESULT MatchProfiles(const Profile &target, const Profile &source, std::wstring &detail) {
    if (target.major != source.major || target.minor != source.minor || target.build != source.build) {
        detail = L"修复源与目标 Windows 版本不一致。";
        return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    }
    if (!EqualI(target.edition, source.edition) || !EqualI(target.type, source.type)) {
        detail = L"请选择与目标版本（Edition）及安装类型一致的修复源。";
        return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    }
    if (source.revision < target.revision) {
        detail = L"修复源更新级别低于目标。请为来源补齐累积更新，或选择匹配的系统源。";
        return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    }
    for (const auto &language : target.languages)
        if (std::none_of(source.languages.begin(), source.languages.end(),
                         [&](const auto &x) { return EqualI(x, language); })) {
            detail = L"修复源缺少目标语言：" + language;
            return HRESULT_FROM_WIN32(ERROR_RESOURCE_LANG_NOT_FOUND);
        }
    return S_OK;
}
struct SourceLease {
    HANDLE handle = INVALID_HANDLE_VALUE;
    OwnedRepairMount mount;
    HRESULT Close() {
        HRESULT hr = mount.Close();
        if (hr != S_OK)
            return hr;
        if (handle != INVALID_HANDLE_VALUE) {
            HANDLE old = handle;
            handle = INVALID_HANDLE_VALUE;
            if (!CloseHandle(old))
                return WinError();
        }
        return S_OK;
    }
    ~SourceLease() {
        Close();
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
};
HRESULT ValidateNetworkSource(const CbsOptions &o, std::wstring &detail) {
    if (!o.repairWorkRoot.empty() &&
        (o.online || o.sourceKind != RepairSourceKind::Wim || o.operation != CbsOperation::Restore ||
         !DriveRootSyntax(o.repairWorkRoot))) {
        detail = L"工作分区仅用于离线 WIM 修复来源。";
        return E_INVALIDARG;
    }
    if (o.sourceKind == RepairSourceKind::WindowsUpdate) {
        if (!o.online) {
            detail = L"Windows Update 修复来源仅支持当前运行的 Windows；离线目标请使用匹配的 WIM 或 Windows "
                     L"目录。";
            return E_NOTIMPL;
        }
        if (o.operation != CbsOperation::Restore) {
            detail = L"Windows Update 来源仅用于修复，不用于 ScanHealth。";
            return E_INVALIDARG;
        }
        if (!o.fullPayloadCheck) {
            detail = L"Windows Update 模式需要完整负载校验。";
            return E_INVALIDARG;
        }
        if (!o.source.empty() || o.sourceIndex) {
            detail = L"Windows Update 模式不接受本地来源路径或 WIM 索引。";
            return E_INVALIDARG;
        }
    }
    if (o.sourceKind == RepairSourceKind::LocalOnly && (!o.source.empty() || o.sourceIndex)) {
        detail = L"仅本地策略不接受外部来源参数。";
        return E_INVALIDARG;
    }
    return S_OK;
}
HRESULT PrepareSource(const CbsOptions &o, const std::wstring &root, const std::wstring &hostWindows,
                      std::wstring &source, std::wstring &detail, const CbsProgress &progress,
                      SourceLease &lease, std::atomic_bool &cancel) {
    if (o.sourceKind == RepairSourceKind::Default)
        return S_OK;
    if (o.sourceKind == RepairSourceKind::LocalOnly)
        return ValidateNetworkSource(o, detail);
    auto networkHr = ValidateNetworkSource(o, detail);
    if (networkHr != S_OK)
        return networkHr;
    if (o.sourceKind == RepairSourceKind::WindowsUpdate) {
        Report(progress, -1,
               L"修复来源：Windows Update；CBS "
               L"在需要修复内容时联网获取，仍受系统策略控制，不保证每次发生下载。可能使用计量网络。");
        return S_OK;
    }
    if (o.sourceKind != RepairSourceKind::Directory && o.sourceKind != RepairSourceKind::Wim) {
        detail = L"未知修复来源类型。";
        return E_INVALIDARG;
    }
    if (o.operation != CbsOperation::Restore) {
        detail = L"修复源仅用于 RestoreHealth。";
        return E_INVALIDARG;
    }
    HRESULT hr = EnablePrivilege(SE_BACKUP_NAME);
    if (hr != S_OK)
        return hr;
    hr = EnablePrivilege(SE_RESTORE_NAME);
    if (hr != S_OK)
        return hr;
    Profile target, media;
    hr = ReadProfile(Join(root, L"Windows"), o.online, target, progress);
    if (hr != S_OK) {
        detail = L"无法完整读取目标版本、更新级别和语言；尚未创建维护会话。";
        return hr;
    }
    Report(progress, -1, L"目标：" + ProfileText(target));
    auto path = Canonical(o.source);
    if (path.empty() || StartsI(path, L"\\\\") ||
        (o.sourceKind == RepairSourceKind::Wim && !OrdinaryPath(path))) {
        detail = L"请选择本地可访问的 WIM 文件或完整 Windows 目录。";
        return E_INVALIDARG;
    }
    if (o.sourceKind == RepairSourceKind::Wim) {
        // Keep the exact WIM file readable and prevent write/delete/replacement
        // from preflight through release of every CBS interface and CbsCore.
        lease.handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (lease.handle == INVALID_HANDLE_VALUE) {
            detail = L"无法锁定修复 WIM；请确认文件存在、可读，且未被写入。";
            return WinError();
        }
        WimResult result;
        auto images = EnumerateWim(path, result);
        if (result.hr != S_OK) {
            detail = L"读取修复 WIM 失败：" + result.detail;
            return result.hr;
        }
        auto image = std::find_if(images.begin(), images.end(),
                                  [&](const auto &x) { return x.index == o.sourceIndex; });
        if (image == images.end()) {
            detail = L"修复 WIM 中不存在所选映像序号。";
            return E_INVALIDARG;
        }
        if (image->architecture != L"9") {
            detail = L"修复 WIM 必须是 x64 架构。";
            return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
        }
        media.major = image->major;
        media.minor = image->minor;
        media.build = image->build;
        media.revision = image->revision;
        media.edition = image->edition;
        media.type = image->installationType;
        media.languages = image->languages;
        if (!media.major || !media.build || media.edition.empty() || media.type.empty() ||
            media.languages.empty()) {
            detail = L"修复 WIM 缺少必要的版本、版本类型或语言元数据。";
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        source = L"wim:" + path + L":" + std::to_wstring(o.sourceIndex);
    } else if (o.sourceKind == RepairSourceKind::Directory) {
        if (!Exists(Join(path, L"System32\\config\\SOFTWARE")))
            path = Join(path, L"Windows");
        const auto ntdll = Join(path, L"System32\\ntdll.dll");
        if (SameFile(ntdll, Join(root, L"Windows\\System32\\ntdll.dll"))) {
            detail = L"修复源就是受维护目标，请选择独立且健康的 Windows 来源。";
            return E_INVALIDARG;
        }
        hr = ReadProfile(path, SameFile(ntdll, Join(hostWindows, L"System32\\ntdll.dll")), media, progress);
        if (hr != S_OK) {
            detail = L"目录必须是可读取完整元数据的 Windows 安装目录；单独的 sources\\sxs 不足以验证来源。";
            return hr;
        }
        lease.handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (lease.handle == INVALID_HANDLE_VALUE) {
            detail = L"无法保持修复目录可访问。";
            return WinError();
        }
        source = path;
    } else
        return E_INVALIDARG;
    Report(progress, -1, L"来源：" + ProfileText(media));
    hr = MatchProfiles(target, media, detail);
    if (hr != S_OK)
        return hr;
    if (media.revision > target.revision)
        Report(progress, -1,
               L"来源更新级别高于目标；元数据匹配不能保证来源仍包含目标需要的旧组件。CBS 将验证实际组件。");
    if (o.sourceKind == RepairSourceKind::Wim && !o.online) {
        if (cancel.load())
            return kCancelled;
        Report(progress, -1, L"正在以只读方式加载修复映像");
        hr = lease.mount.Open(path, o.sourceIndex, cancel, progress,
                              o.repairWorkRoot.empty() ? o.root : o.repairWorkRoot);
        if (hr != S_OK) {
            detail = L"无法只读加载修复 WIM：" + lease.mount.ErrorDetail() +
                     L"。请核对工作分区、WIM 路径与挂载组件；也可手动只读挂载后选择目录来源。";
            return hr;
        }
        source = lease.mount.Windows();
        if (!IsX64Image(Join(source, L"System32\\ntdll.dll"))) {
            detail = L"已加载的修复映像没有有效的 x64 Windows 目录。";
            return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
        }
        Report(progress, -1, L"已加载只读修复来源：" + source);
    }
    Report(progress, -1,
           L"来源元数据已匹配；仍需由 CBS 核对组件清单、目录和负载，不能保证全部损坏均可修复。");
    return S_OK;
}

LONG gModuleRefs = 0;
BOOL WINAPI InitTrue() {
    return TRUE;
}
void WINAPI InitNoop() {}
void WINAPI InitRef() {
    InterlockedIncrement(&gModuleRefs);
}
void WINAPI InitUnref() {
    InterlockedDecrement(&gModuleRefs);
}
using InitFn = HRESULT(WINAPI *)(IMalloc *, decltype(&InitTrue), decltype(&InitNoop), decltype(&InitRef),
                                 decltype(&InitUnref), decltype(&InitNoop), decltype(&InitNoop), IUnknown **);
struct Offline {
    Hive software, system;
    HMODULE module = nullptr;
    Ref factory;
    IMalloc *allocator = nullptr;
    bool initialized = false;
    std::wstring oldPath, oldLog, logPath;
    bool pathChanged = false, dllDirChanged = false, logChanged = false, logExisted = false;
    HRESULT Close() {
        factory.reset();
        if (module && initialized) {
            auto f = reinterpret_cast<void(WINAPI *)()>(GetProcAddress(module, "CbsCoreFinalize"));
            if (f)
                f();
            initialized = false;
        }
        if (module) {
            FreeLibrary(module);
            module = nullptr;
        }
        if (allocator) {
            allocator->Release();
            allocator = nullptr;
        }
        if (dllDirChanged) {
            SetDllDirectoryW(nullptr);
            dllDirChanged = false;
        }
        if (pathChanged) {
            SetEnvironmentVariableW(L"PATH", oldPath.c_str());
            pathChanged = false;
        }
        if (logChanged) {
            SetEnvironmentVariableW(L"COMPONENT_BASED_SERVICING_LOGFILE",
                                    logExisted ? oldLog.c_str() : nullptr);
            logChanged = false;
        }
        HRESULT a = system.Close(), b = software.Close();
        return a != S_OK ? a : b;
    }
    ~Offline() {
        Close();
    }
    HRESULT Create(const std::wstring &root, IUnknown **out) {
        wchar_t hostWindows[MAX_PATH + 1]{};
        UINT count = GetWindowsDirectoryW(hostWindows, MAX_PATH + 1);
        if (!count || count > MAX_PATH)
            return WinError(count ? ERROR_INSUFFICIENT_BUFFER : GetLastError());
        logPath = Join(hostWindows, L"Logs\\CBS\\OfflineCbs.log");
        SetLastError(ERROR_SUCCESS);
        DWORD logSize = GetEnvironmentVariableW(L"COMPONENT_BASED_SERVICING_LOGFILE", nullptr, 0);
        logExisted = logSize != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
        if (logSize) {
            std::vector<wchar_t> value(logSize + 1);
            if (!GetEnvironmentVariableW(L"COMPONENT_BASED_SERVICING_LOGFILE", value.data(),
                                         static_cast<DWORD>(value.size())))
                return WinError();
            oldLog = value.data();
        }
        if (!SetEnvironmentVariableW(L"COMPONENT_BASED_SERVICING_LOGFILE", logPath.c_str()))
            return WinError();
        logChanged = true;
        HRESULT hr = EnablePrivilege(SE_BACKUP_NAME);
        if (hr != S_OK)
            return hr;
        hr = EnablePrivilege(SE_RESTORE_NAME);
        if (hr != S_OK)
            return hr;
        GUID id{};
        hr = CoCreateGuid(&id);
        if (hr != S_OK)
            return hr;
        wchar_t idText[40];
        StringFromGUID2(id, idText, 40);
        std::wstring prefix = L"ReaServicing_" + std::to_wstring(GetCurrentProcessId()) + L"_" + idText;
        hr = software.Load(Join(root, L"Windows\\System32\\config\\SOFTWARE"), prefix + L"_SOFTWARE");
        if (hr != S_OK)
            return hr;
        hr = system.Load(Join(root, L"Windows\\System32\\config\\SYSTEM"), prefix + L"_SYSTEM");
        if (hr != S_OK)
            return hr;
        std::wstring stack;
        hr = StackFromSoftware(software.key, root, stack);
        if (hr != S_OK)
            return hr;
        // CbsCore loads these files under its own fixed offline namespace.
        // A second mount under our random metadata name keeps the file locked
        // and makes real InitializeSession fail with STATUS_SHARING_VIOLATION.
        // Metadata reads are complete; release our mounts before engine init.
        HRESULT systemClose = system.Close(), softwareClose = software.Close();
        if (systemClose != S_OK)
            return systemClose;
        if (softwareClose != S_OK)
            return softwareClose;
        if (!OrdinaryPath(Join(stack, L"CbsCore.dll")))
            return E_ACCESSDENIED;
        if (!IsX64Image(Join(stack, L"CbsCore.dll")))
            return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);
        DWORD n = GetEnvironmentVariableW(L"PATH", nullptr, 0);
        std::vector<wchar_t> path(n + 1);
        if (n && GetEnvironmentVariableW(L"PATH", path.data(), static_cast<DWORD>(path.size())))
            oldPath = path.data();
        std::wstring downlevel = Join(root, L"Windows\\System32\\downlevel");
        if (Exists(downlevel)) {
            if (!OrdinaryPath(downlevel))
                return E_ACCESSDENIED;
            if (!SetEnvironmentVariableW(L"PATH", (downlevel + L";" + oldPath).c_str()))
                return WinError();
            pathChanged = true;
        }
        if (!SetDllDirectoryW(stack.c_str()))
            return WinError();
        dllDirChanged = true;
        module = LoadLibraryExW(Join(stack, L"CbsCore.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!module)
            return WinError();
        auto address = GetProcAddress(module, "CbsCoreInitialize");
        InitFn init = nullptr;
        static_assert(sizeof(init) == sizeof(address), "x64 function pointer size");
        std::memcpy(&init, &address, sizeof(init));
        if (!init || !GetProcAddress(module, "CbsCoreFinalize"))
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        hr = CoGetMalloc(1, &allocator);
        if (hr != S_OK)
            return hr;
        hr = init(allocator, InitTrue, InitNoop, InitRef, InitUnref, InitNoop, InitNoop, factory.put());
        initialized = SUCCEEDED(hr);
        if (hr != S_OK)
            return hr;
        if (!factory.p)
            return E_POINTER;
        hr = Slot<CreateSessionFn>(factory.p, 3)(factory.p, 0, &kSession, out);
        if (hr != S_OK)
            return hr;
        if (!*out)
            return E_POINTER;
        hr = InitializeSession(*out, root.c_str(), Join(root, L"Windows").c_str());
        return hr;
    }
};

} // namespace

CbsResult RunCbs(const CbsOptions &options, std::atomic_bool &cancel, const CbsProgress &progress) {
    CbsResult result;
    auto error = [&](HRESULT hr, const wchar_t *stage, const std::wstring &detail) {
        result.hr = hr;
        result.stage = stage;
        result.detail = detail;
        result.cancelRequested = cancel.load();
        return result;
    };
#ifndef _WIN64
    return error(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), L"平台检查",
                 L"该 CBS ABI 仅恢复并构建了 x64 版本。");
#endif
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"))
        return error(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED), L"平台检查",
                     L"Wine 不提供真实 Windows CBS；不会尝试维护宿主环境。");
    if (cancel.load())
        return error(kCancelled, L"开始前取消", L"尚未创建维护会话。");
    MaintenanceLock operationLock;
    if (operationLock.Result() != S_OK)
        return error(operationLock.Result(), L"维护互斥",
                     L"已有 ADism 维护任务或上次任务异常退出；请核对系统状态后重试。");
    std::wstring networkDetail;
    HRESULT networkHr = ValidateNetworkSource(options, networkDetail);
    if (networkHr != S_OK)
        return error(networkHr, L"修复源检查", networkDetail);
    wchar_t windows[MAX_PATH + 1]{};
    if (!GetWindowsDirectoryW(windows, MAX_PATH))
        return error(WinError(), L"系统路径", L"无法取得 Windows 目录。");
    std::wstring win = windows;
    size_t slash = win.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return error(E_UNEXPECTED, L"系统路径", L"Windows 目录无效。");
    const std::wstring onlineRoot = Canonical(win.substr(0, slash));
    std::wstring root = options.online ? onlineRoot : Canonical(options.root);
    if (!options.online) {
        LocalRoot target, host;
        HRESULT check = InspectRoot(options.root, target);
        if (check != S_OK || target.readOnly)
            return error(check != S_OK ? check : E_ACCESSDENIED, L"目标检查",
                         L"离线目标必须是可写的本地基本分区根目录。");
        check = InspectRoot(onlineRoot, host);
        if (check == S_OK && !_wcsicmp(target.volume.c_str(), host.volume.c_str()))
            return error(E_ACCESSDENIED, L"目标检查", L"离线目标映射到当前 Windows 卷，请使用在线模式。");
        for (auto file : {L"Windows\\System32\\ntdll.dll", L"Windows\\System32\\config\\SYSTEM",
                          L"Windows\\System32\\config\\SOFTWARE"})
            if (!OrdinaryPath(Join(root, file)))
                return error(E_ACCESSDENIED, L"目标检查", L"离线 Windows 关键路径无效或经过重解析点。");
    }
    if (root.empty() || StartsI(root, L"\\\\"))
        return error(E_INVALIDARG, L"目标检查",
                     L"请选择本机磁盘上的 Windows 根目录（包含 Windows 子目录）。");
    if (!options.online && _wcsicmp(root.c_str(), onlineRoot.c_str()) == 0)
        return error(E_INVALIDARG, L"目标检查", L"目标是当前运行系统，请选择在线模式。");
    std::wstring ntdll = Join(root, L"Windows\\System32\\ntdll.dll");
    if (!options.online && SameFile(ntdll, Join(onlineRoot, L"Windows\\System32\\ntdll.dll")))
        return error(E_INVALIDARG, L"目标检查", L"目标映射到当前运行系统，请选择在线模式。");
    if (!IsX64Image(ntdll))
        return error(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), L"体系结构检查",
                     L"目标必须是 x64 Windows；不会加载跨体系结构维护堆栈。");
    DWORD major = 0, minor = 0;
    HRESULT hr = TargetVersion(ntdll, major, minor);
    if (hr != S_OK)
        return error(hr, L"版本检查", L"无法读取目标 ntdll 版本。");
    if (!VersionSupported(major, minor))
        return error(E_NOINTERFACE, L"版本检查", L"当前 CBS 健康接口不支持 Windows 6.0/6.1。");
    if (cancel.load())
        return error(kCancelled, L"开始前取消", L"尚未创建维护会话。");
    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return error(hr, L"COM 初始化", L"请在独立工作进程中运行 CBS。");
    struct ComExit {
        ~ComExit() {
            CoUninitialize();
        }
    } com;
    hr = InitSecurity();
    if (hr != S_OK)
        return error(hr, L"COM 安全初始化", L"无法按恢复的 CBSHost 安全设置创建工作进程。");
    std::wstring repairSource, sourceDetail;
    SourceLease sourceLease;
    auto finishSource = [&](CbsResult r) {
        std::wstring path = sourceLease.mount.Path();
        HRESULT clean = sourceLease.Close();
        if (clean != S_OK) {
            auto message = L"修复来源清理失败 " + Hex(clean) + L"；自有挂载位置：" + path +
                           L"。请保持来源可用并检查挂载状态。";
            if (r.hr == S_OK) {
                r.hr = clean;
                r.stage = L"卸载只读修复来源";
                r.detail = message;
                r.imageStateUnknown = true;
            } else
                r.detail += L" " + message;
        }
        return r;
    };
    hr = PrepareSource(options, root, win, repairSource, sourceDetail, progress, sourceLease, cancel);
    if (hr != S_OK)
        return finishSource(error(hr, L"修复源检查", sourceDetail));
    if (cancel.load())
        return finishSource(error(kCancelled, L"开始前取消", L"来源检查后取消，尚未创建维护会话。"));
    Ref session;
    Offline offline;
    if (options.online) {
        Report(progress, -1, L"连接当前 Windows 的 CBS 服务");
        hr = CoCreateInstance(kSessionClass, nullptr, 0x0f, kSession,
                              reinterpret_cast<void **>(session.put()));
        if (hr == S_OK && session.p)
            hr = InitializeSession(session.p, nullptr, nullptr);
        else if (hr == S_OK)
            hr = E_POINTER;
    } else {
        Report(progress, -1, L"初始化目标 Windows 的离线 CBS 维护堆栈");
        hr = offline.Create(root, session.put());
    }
    if (hr != S_OK) {
        session.reset();
        HRESULT cleanup = offline.Close();
        result.cbsLog = options.online ? Join(onlineRoot, L"Windows\\Logs\\CBS\\CBS.log") : offline.logPath;
        std::wstring detail = L"CBS 初始化失败，状态 " + Hex(hr) + L"。没有改用其他修复引擎。";
        if (cleanup != S_OK)
            detail += L" 清理元数据 hive 也失败：" + Hex(cleanup) + L"；请核对遗留挂载。";
        return finishSource(error(hr, L"创建 CBS 会话", detail));
    }
    IUnknown *owned = session.p;
    session.p = nullptr;
    result = Drive(owned, options.operation, cancel, progress, repairSource, options.fullPayloadCheck,
                   options.sourceKind);
    HRESULT cleanup = offline.Close();
    result.cbsLog = options.online ? Join(onlineRoot, L"Windows\\Logs\\CBS\\CBS.log") : offline.logPath;
    if (result.hr == S_OK && cleanup != S_OK) {
        result.hr = cleanup;
        result.stage = L"卸载离线元数据 hive";
        result.detail = L"CBS 已返回成功，但本进程挂载的元数据 hive 未能全部卸载。";
    } else if (result.hr != S_OK) {
        auto prior = result.detail;
        result.detail = L"阶段：" + result.stage + L"；状态：" + Hex(result.hr) + L"。请结合 CBS 日志核对。";
        if (!prior.empty())
            result.detail += L" " + prior;
        if (cleanup != S_OK)
            result.detail += L" 清理元数据 hive 也失败：" + Hex(cleanup) + L"；请核对遗留挂载。";
    }
    if (result.hr == static_cast<HRESULT>(0x800f081fu))
        result.detail += L" 找不到所需修复组件。请指定匹配版本、语言且更新级别足够的系统源；同版本 ISO "
                         L"也可能缺少历史组件。";
    else if (result.hr == static_cast<HRESULT>(0x800f0906u))
        result.detail += L" 无法下载修复内容；请检查网络和更新策略，或指定本地匹配来源。";
    if (result.imageStateUnknown)
        result.detail += result.cancelRequested ? L" 已请求取消；镜像最终状态未确认，请重新扫描后再继续。"
                                                : L" 维护未完成；镜像最终状态未确认，请重新扫描后再继续。";
    if (result.requiredActionAvailable)
        result.detail += L" CBS 所需动作（原始值）：" + std::to_wstring(result.requiredAction) + L"。";
    return finishSource(result);
}

namespace {
// Deliberately not Windows CBS: deterministic fake raw vtables exercise ABI
// dispatch, status handling, source=NULL semantics and reference lifetimes.
struct Fake {
    void **vtable;
    LONG refs = 1;
    IUnknown *ui = nullptr;
    std::vector<int> events;
    HRESULT init = S_OK, sourceResult = S_OK, privateQi = S_OK, enhancedResult = S_OK;
    ULONG enhancedFlags = 0;
    bool initOnline = false;
    std::wstring source;
    ULONG sourceFlags = 99;
    HRESULT qi8 = S_OK, qiexec = S_OK, reg = S_OK, execute = S_OK, prop6 = S_OK, prop3 = S_OK;
    bool corrupt = false, nonrepairable = false, cancelInExecute = false, nullQi = false,
         nullProperty = false;
    std::atomic_bool *cancel = nullptr;
    ULONG flags = 0;
    static HRESULT WINAPI QI(IUnknown *self, REFIID iid, void **out) {
        auto &f = *reinterpret_cast<Fake *>(self);
        *out = nullptr;
        HRESULT hr = IsEqualGUID(iid, kSession8)       ? f.qi8
                     : IsEqualGUID(iid, kExecutor)     ? f.qiexec
                     : IsEqualGUID(iid, kFullSession9) ? f.privateQi
                                                       : E_NOINTERFACE;
        f.events.push_back(IsEqualGUID(iid, kSession8) ? 10 : IsEqualGUID(iid, kFullSession9) ? 12 : 11);
        if (hr == S_OK && !f.nullQi) {
            *out = self;
            ++f.refs;
        }
        return hr;
    }
    static HRESULT WINAPI Init(IUnknown *self, ULONG, LPCWSTR, LPCWSTR root, LPCWSTR windows) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.initOnline = !root && !windows;
        return f.init;
    }
    static ULONG WINAPI Add(IUnknown *self) {
        return ++reinterpret_cast<Fake *>(self)->refs;
    }
    static ULONG WINAPI Release(IUnknown *self) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(20);
        LONG n = --f.refs;
        if (!n && f.ui) {
            f.ui->Release();
            f.ui = nullptr;
        }
        return n;
    }
    static HRESULT WINAPI Register(IUnknown *self, IUnknown *ui) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(30);
        if (f.reg == S_OK) {
            f.ui = ui;
            ui->AddRef();
        }
        return f.reg;
    }
    static HRESULT WINAPI Exec(IUnknown *self, ULONG flags, ULONG *) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(40);
        f.flags = flags;
        if (f.cancelInExecute && f.cancel)
            f.cancel->store(true);
        if (f.ui) {
            ULONGLONG action = 0;
            Slot<HRESULT(WINAPI *)(IUnknown *, ULONG, ULONG, ULONG, ULONGLONG *)>(f.ui, 7)(f.ui, 0, 5, 10,
                                                                                           &action);
            if (f.cancelInExecute && action != 2)
                return E_UNEXPECTED;
        }
        return f.execute;
    }
    static HRESULT WINAPI Enhanced(IUnknown *self, ULONG flags) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(25);
        f.enhancedFlags = flags;
        return f.enhancedResult;
    }
    static HRESULT WINAPI Source(IUnknown *self, ULONG flags, LPCWSTR source) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(35);
        f.sourceFlags = flags;
        f.source = source ? source : L"";
        return f.sourceResult;
    }
    static HRESULT WINAPI Property(IUnknown *self, ULONG id, LPCWSTR *out) {
        auto &f = *reinterpret_cast<Fake *>(self);
        f.events.push_back(id == 6 ? 50 : 51);
        HRESULT hr = id == 6 ? f.prop6 : f.prop3;
        *out = f.nullProperty ? nullptr : ((id == 6 ? f.corrupt : f.nonrepairable) ? L"1" : L"0");
        return hr;
    }
};
std::array<void *, 24> FakeTable() {
    std::array<void *, 24> v{};
    v[0] = reinterpret_cast<void *>(&Fake::QI);
    v[1] = reinterpret_cast<void *>(&Fake::Add);
    v[2] = reinterpret_cast<void *>(&Fake::Release);
    v[3] = reinterpret_cast<void *>(&Fake::Init);
    v[12] = reinterpret_cast<void *>(&Fake::Property);
    v[14] = reinterpret_cast<void *>(&Fake::Exec);
    v[16] = reinterpret_cast<void *>(&Fake::Register);
    v[15] = reinterpret_cast<void *>(&Fake::Source);
    v[23] = reinterpret_cast<void *>(&Fake::Enhanced);
    return v;
}
} // namespace
int CbsSelfTest() {
    int fails = 0;
    auto v = FakeTable();
    auto run = [&](Fake &f, CbsOperation op, std::atomic_bool &cancel) {
        f.vtable = v.data();
        f.cancel = &cancel;
        return Drive(reinterpret_cast<IUnknown *>(&f), op, cancel, {});
    };
    for (int state = 0; state < 3; ++state) {
        Fake f{};
        f.corrupt = state != 0;
        f.nonrepairable = state == 2;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr != S_OK || r.health != state || f.flags != 0x4100 || f.refs != 0 || f.ui)
            ++fails;
    }
    {
        Fake f{};
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Restore, c);
        if (r.hr != S_OK || r.health != -1 || f.flags != 0x8100 || f.refs != 0)
            ++fails;
        auto firstRelease = std::find(f.events.begin(), f.events.end(), 20),
             exec = std::find(f.events.begin(), f.events.end(), 40);
        if (firstRelease >= exec)
            ++fails;
    }
    for (int failure = 0; failure < 5; ++failure) {
        Fake f{};
        if (failure == 0)
            f.qi8 = E_NOINTERFACE;
        if (failure == 1)
            f.reg = E_ACCESSDENIED;
        if (failure == 2)
            f.qiexec = E_NOINTERFACE;
        if (failure == 3)
            f.execute = E_FAIL;
        if (failure == 4)
            f.prop6 = E_FAIL;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr == S_OK || r.health != -1 || f.refs != 0 || f.ui)
            ++fails;
    }
    {
        Fake f{};
        f.corrupt = true;
        f.prop3 = E_FAIL;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr != E_FAIL || r.health != -1 || f.refs != 0)
            ++fails;
    }
    {
        Fake f{};
        f.execute = static_cast<HRESULT>(0x800f0820u);
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Restore, c);
        if (r.hr != kCancelled || !r.imageStateUnknown || f.refs != 0)
            ++fails;
    }
    {
        Fake f{};
        f.cancelInExecute = true;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Restore, c);
        if (r.hr != kCancelled || !r.cancelRequested || !r.imageStateUnknown || f.refs != 0)
            ++fails;
    }
    {
        Fake f{};
        std::atomic_bool c{true};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr != kCancelled || !r.cancelRequested || f.refs != 0 ||
            (!f.events.empty() && f.events.front() != 20))
            ++fails;
    }
    {
        Fake f{};
        f.execute = S_FALSE;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Restore, c);
        if (r.hr != S_FALSE || r.stage != L"执行 CBS 操作" || f.refs != 0)
            ++fails;
    }
    {
        Fake f{};
        f.nullQi = true;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr != E_NOINTERFACE || f.refs != 0)
            ++fails;
    }
    {
        Fake f{};
        f.nullProperty = true;
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Scan, c);
        if (r.hr != E_POINTER || f.refs != 0)
            ++fails;
    }
    {
        std::atomic_bool c{true};
        Ui *ui = new Ui(c, {});
        ULONGLONG action = 0;
        ui->QueryAction(0, 0, 0, 0, &action);
        void *p = nullptr;
        if (action != 2 || ui->QueryInterface(IID_IMarshal, &p) != E_NOINTERFACE || p)
            ++fails;
        ui->Release();
    }
    {
        Fake f{};
        f.vtable = v.data();
        f.init = E_ACCESSDENIED;
        if (InitializeSession(reinterpret_cast<IUnknown *>(&f), nullptr, nullptr) != E_ACCESSDENIED ||
            !f.initOnline || InitializeSession(nullptr, nullptr, nullptr) != E_POINTER)
            ++fails;
    }
    if (Canonical(L"C:") != L"C:" || !Canonical(L"").empty() ||
        !Canonical(L"\\\\?\\UNC\\server\\share").empty())
        ++fails;
    if (VersionSupported(6, 0) || VersionSupported(6, 1) || !VersionSupported(6, 2) ||
        !VersionSupported(10, 0))
        ++fails;
    if (ExpandTarget(L"%SystemRoot%\\WinSxS", L"D:\\mount") != L"D:\\mount\\Windows\\WinSxS")
        ++fails;
    if (ExpandTarget(L"%SystemDrive%\\Windows", L"D:\\mount") != L"D:\\mount\\Windows")
        ++fails;
    {
        Fake f{};
        f.vtable = v.data();
        std::atomic_bool c{false};
        auto r =
            Drive(reinterpret_cast<IUnknown *>(&f), CbsOperation::Restore, c, {}, L"wim:D:\\install.wim:3");
        auto source = std::find(f.events.begin(), f.events.end(), 35),
             execute = std::find(f.events.begin(), f.events.end(), 40);
        if (r.hr != S_OK || f.source != L"wim:D:\\install.wim:3" || f.sourceFlags || source >= execute ||
            f.refs)
            ++fails;
    }
    {
        Fake f{};
        f.vtable = v.data();
        f.sourceResult = E_ACCESSDENIED;
        std::atomic_bool c{false};
        auto r = Drive(reinterpret_cast<IUnknown *>(&f), CbsOperation::Restore, c, {}, L"D:\\mount\\Windows");
        if (r.hr != E_ACCESSDENIED || std::find(f.events.begin(), f.events.end(), 40) != f.events.end() ||
            f.refs)
            ++fails;
    }
    {
        Fake f{};
        std::atomic_bool c{false};
        auto r = run(f, CbsOperation::Restore, c);
        if (r.hr != S_OK || std::find(f.events.begin(), f.events.end(), 35) != f.events.end())
            ++fails;
    }
    {
        Fake f{};
        f.vtable = v.data();
        f.sourceResult = S_FALSE;
        std::atomic_bool c{false};
        auto r =
            Drive(reinterpret_cast<IUnknown *>(&f), CbsOperation::Restore, c, {}, L"wim:D:\\install.wim:3");
        if (r.hr != E_UNEXPECTED || r.detail.find(L"0x00000001") == std::wstring::npos ||
            std::find(f.events.begin(), f.events.end(), 40) != f.events.end() || f.refs)
            ++fails;
    }
    for (auto op : {CbsOperation::Scan, CbsOperation::Restore}) {
        Fake f{};
        f.vtable = v.data();
        std::atomic_bool c{false};
        auto r = Drive(reinterpret_cast<IUnknown *>(&f), op, c, {}, L"", true);
        auto enhanced = std::find(f.events.begin(), f.events.end(), 25),
             execute = std::find(f.events.begin(), f.events.end(), 40);
        if (r.hr != S_OK || f.enhancedFlags != (op == CbsOperation::Scan ? 0x800u : 0x1000u) ||
            f.flags != 0 || enhanced >= execute || f.refs)
            ++fails;
    }
    for (int fault = 0; fault < 2; ++fault) {
        Fake f{};
        f.vtable = v.data();
        if (fault == 0)
            f.privateQi = E_NOINTERFACE;
        else
            f.enhancedResult = E_ACCESSDENIED;
        std::atomic_bool c{false};
        auto r = Drive(reinterpret_cast<IUnknown *>(&f), CbsOperation::Restore, c, {}, L"", true);
        if (SUCCEEDED(r.hr) || std::find(f.events.begin(), f.events.end(), 40) != f.events.end() || f.refs)
            ++fails;
    }
    for (auto policy : {RepairSourceKind::WindowsUpdate, RepairSourceKind::LocalOnly}) {
        Fake f{};
        f.vtable = v.data();
        std::atomic_bool c{false};
        auto r = Drive(reinterpret_cast<IUnknown *>(&f), CbsOperation::Restore, c, {}, L"", true, policy);
        if (r.hr != S_OK || f.flags != (policy == RepairSourceKind::WindowsUpdate ? 0x40000u : 0x20000u) ||
            f.enhancedFlags != 0x1000u || !f.source.empty() || f.refs)
            ++fails;
    }
    for (int invalid = 0; invalid < 5; ++invalid) {
        CbsOptions o;
        o.sourceKind = RepairSourceKind::WindowsUpdate;
        o.operation = CbsOperation::Restore;
        if (invalid == 0)
            o.online = false;
        if (invalid == 1)
            o.fullPayloadCheck = false;
        if (invalid == 2)
            o.source = L"D:\\Windows";
        if (invalid == 3)
            o.sourceIndex = 3;
        if (invalid == 4)
            o.operation = CbsOperation::Scan;
        std::wstring source, detail;
        SourceLease lease;
        std::atomic_bool c{false};
        auto hr = PrepareSource(o, L"C:", L"C:\\Windows", source, detail, {}, lease, c);
        if (SUCCEEDED(hr) || detail.empty())
            ++fails;
    }
    {
        Profile t;
        t.major = 10;
        t.build = 26100;
        t.revision = 2314;
        t.edition = L"Professional";
        t.type = L"Client";
        t.languages = {L"zh-CN"};
        std::wstring detail;
        if (MatchProfiles(t, t, detail) != S_OK)
            ++fails;
        auto media = t;
        media.build = 22621;
        if (SUCCEEDED(MatchProfiles(t, media, detail)))
            ++fails;
        media = t;
        media.revision = 1;
        if (SUCCEEDED(MatchProfiles(t, media, detail)))
            ++fails;
        media = t;
        media.edition = L"Enterprise";
        if (SUCCEEDED(MatchProfiles(t, media, detail)))
            ++fails;
        media = t;
        media.languages = {L"en-US"};
        if (SUCCEEDED(MatchProfiles(t, media, detail)))
            ++fails;
        media = t;
        media.languages = {L"zh-cn", L"en-US"};
        if (MatchProfiles(t, media, detail) != S_OK)
            ++fails;
    }
    return fails;
}
} // namespace servicing
