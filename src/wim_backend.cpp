// SPDX-License-Identifier: GPL-3.0-only
#include "win_util.h"
#include "wim_backend.h"
#include "boot_backend.h"
#include "safety.h"
#include <filesystem>
#include <algorithm>
#include <cwctype>
#include <sstream>
#include <winver.h>
#include <msxml6.h>
namespace servicing {
namespace {
namespace fs = std::filesystem;
HRESULT Err() {
    DWORD e = GetLastError();
    return HRESULT_FROM_WIN32(e ? e : ERROR_GEN_FAILURE);
}
struct Handle {
    HANDLE h = nullptr;
    BOOL(WINAPI *close)(HANDLE) = nullptr;
    ~Handle() {
        if (h && h != INVALID_HANDLE_VALUE && close)
            close(h);
    }
};
struct Api {
    HMODULE dll = nullptr;
    DWORD versionMS = 0, versionLS = 0;
    HANDLE(WINAPI *create)(PCWSTR, DWORD, DWORD, DWORD, DWORD, PDWORD) = nullptr;
    BOOL(WINAPI *close)(HANDLE) = nullptr;
    DWORD(WINAPI *count)(HANDLE) = nullptr;
    HANDLE(WINAPI *load)(HANDLE, DWORD) = nullptr;
    BOOL(WINAPI *info)(HANDLE, PVOID *, PDWORD) = nullptr;
    BOOL(WINAPI *temp)(HANDLE, PCWSTR) = nullptr;
    DWORD(WINAPI *reg)(HANDLE, FARPROC, PVOID) = nullptr;
    BOOL(WINAPI *unreg)(HANDLE, FARPROC) = nullptr;
    BOOL(WINAPI *apply)(HANDLE, PCWSTR, DWORD) = nullptr;
    Api(bool fake = false) {
        if (fake)
            return;
        dll = LoadLibraryExW(L"wimgapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!dll)
            return;
        wchar_t module[32768];
        if (GetModuleFileNameW(dll, module, 32768)) {
            DWORD ignored = 0, n = GetFileVersionInfoSizeW(module, &ignored);
            std::vector<BYTE> b(n);
            if (n && GetFileVersionInfoW(module, 0, n, b.data())) {
                VS_FIXEDFILEINFO *f = nullptr;
                UINT len = 0;
                if (VerQueryValueW(b.data(), L"\\", reinterpret_cast<void **>(&f), &len) &&
                    len >= sizeof(*f)) {
                    versionMS = f->dwFileVersionMS;
                    versionLS = f->dwFileVersionLS;
                }
            }
        }
#define GET(field, name) field = LoadFunction<decltype(field)>(dll, name)
        GET(create, "WIMCreateFile");
        GET(close, "WIMCloseHandle");
        GET(count, "WIMGetImageCount");
        GET(load, "WIMLoadImage");
        GET(info, "WIMGetImageInformation");
        GET(temp, "WIMSetTemporaryPath");
        GET(reg, "WIMRegisterMessageCallback");
        GET(unreg, "WIMUnregisterMessageCallback");
        GET(apply, "WIMApplyImage");
#undef GET
    }
    ~Api() {
        if (dll)
            FreeLibrary(dll);
    }
    bool valid() {
        return create && close && count && load && info && temp && reg && unreg && apply;
    }
};
struct Xml {
    IXMLDOMDocument *doc = nullptr;
    bool com = false;
    Xml(const wchar_t *text, size_t chars) {
        if (chars && text[0] == 0xfeff) {
            ++text;
            --chars;
        }
        HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        com = SUCCEEDED(init);
        if (FAILED(init) && init != RPC_E_CHANGED_MODE)
            return;
        CLSID clsid{};
        if (FAILED(CLSIDFromProgID(L"Msxml2.DOMDocument.6.0", &clsid)))
            return;
        if (FAILED(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, IID_IXMLDOMDocument,
                                    reinterpret_cast<void **>(&doc))))
            return;
        doc->put_async(VARIANT_FALSE);
        doc->put_validateOnParse(VARIANT_FALSE);
        doc->put_resolveExternals(VARIANT_FALSE);
        BSTR input = SysAllocStringLen(text, UINT(chars));
        VARIANT_BOOL loaded = VARIANT_FALSE;
        HRESULT e = input ? doc->loadXML(input, &loaded) : E_OUTOFMEMORY;
        SysFreeString(input);
        if (FAILED(e) || !loaded) {
            doc->Release();
            doc = nullptr;
        }
    }
    ~Xml() {
        if (doc)
            doc->Release();
        if (com)
            CoUninitialize();
    }
    std::vector<std::wstring> All(const wchar_t *path) {
        std::vector<std::wstring> result;
        if (!doc)
            return result;
        BSTR query = SysAllocString(path);
        IXMLDOMNodeList *list = nullptr;
        doc->selectNodes(query, &list);
        SysFreeString(query);
        if (!list)
            return result;
        long count = 0;
        list->get_length(&count);
        for (long i = 0; i < count; ++i) {
            IXMLDOMNode *node = nullptr;
            list->get_item(i, &node);
            if (node) {
                BSTR value = nullptr;
                node->get_text(&value);
                if (value)
                    result.emplace_back(value);
                SysFreeString(value);
                node->Release();
            }
        }
        list->Release();
        return result;
    }
    std::wstring Get(const wchar_t *path) {
        if (!doc)
            return {};
        BSTR query = SysAllocString(path);
        IXMLDOMNode *node = nullptr;
        doc->selectSingleNode(query, &node);
        SysFreeString(query);
        if (!node)
            return {};
        BSTR value = nullptr;
        node->get_text(&value);
        std::wstring result = value ? value : L"";
        SysFreeString(value);
        node->Release();
        return result;
    }
};
unsigned Number(const std::wstring &s) {
    try {
        return unsigned(std::stoul(s));
    } catch (...) {
        return 0;
    }
}
std::wstring Full(const std::wstring &s) {
    DWORD n = GetFullPathNameW(s.c_str(), 0, nullptr, nullptr);
    if (!n)
        return {};
    std::wstring r(n, L'\0');
    if (!GetFullPathNameW(s.c_str(), n, r.data(), nullptr))
        return {};
    r.resize(wcslen(r.c_str()));
    while (r.size() > 3 && r.back() == L'\\')
        r.pop_back();
    return r;
}
std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), towlower);
    return s;
}
bool Within(const std::wstring &child, const std::wstring &parent) {
    auto c = Lower(child), p = Lower(parent);
    if (p.back() != L'\\')
        p += L'\\';
    return c == Lower(parent) || c.compare(0, p.size(), p) == 0;
}
bool VolumeIdentity(const std::wstring &path, std::wstring &identity) {
    wchar_t root[32768], name[32768];
    if (!GetVolumePathNameW(path.c_str(), root, 32768) ||
        !GetVolumeNameForVolumeMountPointW(root, name, 32768))
        return false;
    identity = Lower(name);
    return true;
}
bool RealLocalDrive(const std::wstring &root) {
    if (root.size() != 3 || root[1] != L':' || root[2] != L'\\')
        return false;
    wchar_t device[32768];
    std::wstring drive = root.substr(0, 2);
    if (!QueryDosDeviceW(drive.c_str(), device, 32768))
        return false;
    return wcsncmp(device, L"\\Device\\HarddiskVolume", wcslen(L"\\Device\\HarddiskVolume")) == 0;
}
bool ReparseAncestor(fs::path p) {
    for (; !p.empty();) {
        DWORD a = GetFileAttributesW(p.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT))
            return true;
        auto q = p.parent_path();
        if (q == p)
            break;
        p = q;
    }
    return false;
}
struct Context {
    std::atomic_bool *cancel;
    const WimProgress *progress;
    std::wstring root;
    bool threw = false;
};
DWORD CALLBACK Callback(DWORD m, WPARAM w, LPARAM, void *data) {
    auto *c = static_cast<Context *>(data);
    if (m == 0x948e)
        return c->cancel->load() ? 0xffffffffu : 0u;
    try {
        if (m == 0x9478 || m == 0x948a)
            (*c->progress)(int(w), L"正在释放 WIM");
        else if (m == 0x9479 && w)
            (*c->progress)(-1, reinterpret_cast<PCWSTR>(w));
    } catch (...) {
        c->threw = true;
        c->cancel->store(true);
    }
    return 0;
}
struct ImageSession {
    Api &a;
    Handle file, image;
    Context &context;
    bool registered = false;
    ImageSession(Api &api, Context &ctx) : a(api), context(ctx) {
        file.close = image.close = a.close;
    }
    ~ImageSession() {
        if (registered)
            a.unreg(file.h, FunctionPointer<FARPROC>(&Callback));
    }
    bool Prepare(const std::wstring &source, unsigned index, const wchar_t *scratch) {
        DWORD disposition = 0;
        file.h = a.create(source.c_str(), GENERIC_READ, 3, a.versionMS > 0x60002 ? 0x20000000 : 0, 0,
                          &disposition);
        if (!file.h || file.h == INVALID_HANDLE_VALUE)
            return false;
        if (!a.temp(file.h, scratch))
            return false;
        image.h = a.load(file.h, index);
        if (!image.h || image.h == INVALID_HANDLE_VALUE)
            return false;
        registered = a.reg(file.h, FunctionPointer<FARPROC>(&Callback), &context) != 0xffffffff;
        return registered;
    }
    bool Apply(const std::wstring &root) {
        DWORD flags =
            (a.versionMS > 0xa0000 || (a.versionMS == 0xa0000 && a.versionLS >= 0x38390000)) ? 0x8000 : 0;
        return a.apply(image.h, root.c_str(), flags) != FALSE;
    }
};
struct FakeWim {
    static inline int fail = 0, created = 0, loaded = 0, closedFile = 0, closedImage = 0, unregistered = 0;
    static inline DWORD index = 0, flags = 0, createFlags = 0;
    static inline FARPROC callback = nullptr;
    static inline void *context = nullptr;
    static void Reset(int f) {
        fail = f;
        created = loaded = closedFile = closedImage = unregistered = 0;
        index = flags = createFlags = 0;
        callback = nullptr;
        context = nullptr;
    }
    static HANDLE WINAPI Create(PCWSTR, DWORD, DWORD, DWORD f, DWORD, PDWORD) {
        createFlags = f;
        ++created;
        SetLastError(ERROR_ACCESS_DENIED);
        return fail == 1 ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>(1);
    }
    static BOOL WINAPI Temp(HANDLE, PCWSTR) {
        return fail != 2;
    }
    static HANDLE WINAPI Load(HANDLE, DWORD i) {
        index = i;
        ++loaded;
        return fail == 3 ? nullptr : reinterpret_cast<HANDLE>(2);
    }
    static DWORD WINAPI Register(HANDLE, FARPROC cb, void *ctx) {
        callback = cb;
        context = ctx;
        return fail == 4 ? 0xffffffff : 0;
    }
    static BOOL WINAPI Unregister(HANDLE, FARPROC) {
        ++unregistered;
        return TRUE;
    }
    static BOOL WINAPI Close(HANDLE h) {
        if (h == reinterpret_cast<HANDLE>(1))
            ++closedFile;
        else if (h == reinterpret_cast<HANDLE>(2))
            ++closedImage;
        return TRUE;
    }
    static BOOL WINAPI Apply(HANDLE, PCWSTR, DWORD f) {
        flags = f;
        if (fail == 6) {
            using Cb = DWORD(CALLBACK *)(DWORD, WPARAM, LPARAM, void *);
            if (FunctionPointer<Cb>(callback)(0x948e, 0, 0, context) != 0xffffffffu)
                return TRUE;
            SetLastError(ERROR_CANCELLED);
            return FALSE;
        }
        return fail != 5;
    }
    static void Install(Api &a) {
        a.create = Create;
        a.temp = Temp;
        a.load = Load;
        a.reg = Register;
        a.unreg = Unregister;
        a.close = Close;
        a.apply = Apply;
        a.versionMS = 0xa0000;
        a.versionLS = 0x38390000;
    }
};
int LifecycleTest() {
    for (int failure = 0; failure <= 6; ++failure) {
        FakeWim::Reset(failure);
        Api api(true);
        FakeWim::Install(api);
        std::atomic_bool cancel{failure == 6};
        WimProgress progress = [](int, const std::wstring &) {};
        Context ctx{&cancel, &progress, L"E:\\"};
        {
            ImageSession session(api, ctx);
            bool prepared = session.Prepare(L"fake.wim", 3, L"scratch");
            if (prepared != (failure != 1 && failure != 2 && failure != 3 && failure != 4))
                return 20 + failure;
            if (prepared) {
                bool applied = session.Apply(L"E:\\");
                if (applied != (failure != 5 && failure != 6))
                    return 30 + failure;
            }
        }
        if (FakeWim::closedFile != (failure == 1 ? 0 : 1) ||
            FakeWim::closedImage != ((failure == 1 || failure == 2 || failure == 3) ? 0 : 1) ||
            FakeWim::unregistered != ((failure >= 1 && failure <= 4) ? 0 : 1))
            return 40 + failure;
        if (failure != 1 && failure != 2 && FakeWim::index != 3)
            return 50 + failure;
        if (FakeWim::createFlags != 0x20000000)
            return 60 + failure;
        if ((failure == 0 || failure >= 5) && FakeWim::flags != 0x8000)
            return 70 + failure;
    }
    return 0;
}
struct Privileges {
    HANDLE token = nullptr;
    struct Two {
        DWORD count;
        LUID_AND_ATTRIBUTES entries[2];
    } previous{};
    DWORD previousSize = sizeof(previous);
    bool ok = false;
    Privileges() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return;
        Two request{};
        request.count = 2;
        if (!LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &request.entries[0].Luid) ||
            !LookupPrivilegeValueW(nullptr, SE_RESTORE_NAME, &request.entries[1].Luid))
            return;
        for (auto &entry : request.entries)
            entry.Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(0);
        ok = AdjustTokenPrivileges(token, FALSE, reinterpret_cast<TOKEN_PRIVILEGES *>(&request),
                                   sizeof(previous), reinterpret_cast<TOKEN_PRIVILEGES *>(&previous),
                                   &previousSize) &&
             GetLastError() == 0;
    }
    ~Privileges() {
        if (token) {
            if (previous.count)
                AdjustTokenPrivileges(token, FALSE, reinterpret_cast<TOKEN_PRIVILEGES *>(&previous), 0,
                                      nullptr, nullptr);
            CloseHandle(token);
        }
    }
};
struct Hive {
    HKEY key = nullptr;
    std::wstring name;
    LONG Close() {
        if (key) {
            RegCloseKey(key);
            key = nullptr;
        }
        if (name.empty())
            return 0;
        LONG e = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, name.c_str());
        if (!e)
            name.clear();
        return e;
    }
    ~Hive() {
        Close();
    }
};
LONG Mount(const std::wstring &file, Hive &h) {
    static std::atomic<unsigned> seq{0};
    h.name = L"DismRebuild_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(seq++);
    LONG e = RegLoadKeyW(HKEY_LOCAL_MACHINE, h.name.c_str(), file.c_str());
    if (e) {
        h.name.clear();
        return e;
    }
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, h.name.c_str(), 0, KEY_ALL_ACCESS, &h.key);
}
bool ValidRegistryString(const wchar_t *text, DWORD bytes, size_t capacity) {
    return bytes >= sizeof(wchar_t) && bytes <= capacity * sizeof(wchar_t) && bytes % sizeof(wchar_t) == 0 &&
           text[bytes / sizeof(wchar_t) - 1] == 0;
}
LONG PostWork(const std::wstring &root, bool wtg, Hive &system, Hive &software) {
    LONG e = Mount(root + L"\\Windows\\System32\\config\\SYSTEM", system);
    if (e)
        return e;
    e = Mount(root + L"\\Windows\\System32\\config\\SOFTWARE", software);
    if (e)
        return e;
    wchar_t sr[32768]{};
    DWORD size = sizeof(sr), type = 0;
    HKEY key = nullptr;
    e = RegOpenKeyExW(software.key, L"Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &key);
    if (!e) {
        e = RegQueryValueExW(key, L"SystemRoot", nullptr, &type, reinterpret_cast<BYTE *>(sr), &size);
        RegCloseKey(key);
    }
    if (!e && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        if (!ValidRegistryString(sr, size, std::size(sr)))
            return ERROR_INVALID_DATA;
    }
    if (!e && (type == REG_SZ || type == REG_EXPAND_SZ) && wcslen(sr) > 2 && sr[1] == L':' &&
        sr[2] == L'\\' && sr[0] != L'x' && root.size() > 2 && root[1] == L':') {
        HKEY host = nullptr, target = nullptr;
        BYTE identity[4096];
        DWORD bytes = sizeof(identity);
        std::wstring value = L"\\DosDevices\\" + root.substr(0, 2);
        e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices", 0, KEY_READ, &host);
        if (!e) {
            e = RegQueryValueExW(host, value.c_str(), nullptr, &type, identity, &bytes);
            RegCloseKey(host);
        }
        if (!e && type == REG_BINARY) {
            e = RegCreateKeyExW(system.key, L"MountedDevices", 0, nullptr, 0, KEY_ALL_ACCESS, nullptr,
                                &target, nullptr);
            if (!e) {
                std::wstring wanted = L"\\DosDevices\\";
                wanted += wchar_t(towupper(sr[0]));
                wanted += L":";
                std::vector<std::wstring> remove;
                bool correct = false;
                for (DWORD i = 0;; ++i) {
                    wchar_t name[32768];
                    BYTE data[4096];
                    DWORD nc = 32768, bc = sizeof(data), t;
                    LONG q = RegEnumValueW(target, i, name, &nc, nullptr, &t, data, &bc);
                    if (q == ERROR_NO_MORE_ITEMS)
                        break;
                    if (q) {
                        e = q;
                        break;
                    }
                    if (t == REG_BINARY && bc == bytes && !memcmp(data, identity, bytes)) {
                        if (!_wcsicmp(name, wanted.c_str()))
                            correct = true;
                        else
                            remove.emplace_back(name);
                    }
                }
                if (!e && !correct) {
                    for (auto &n : remove) {
                        e = RegDeleteValueW(target, n.c_str());
                        if (e)
                            break;
                    }
                    if (!e)
                        e = RegSetValueExW(target, wanted.c_str(), 0, REG_BINARY, identity, bytes);
                }
                RegCloseKey(target);
            }
        }
        // Missing host identity is benign in the original mapping adjustment.
        if (e == ERROR_FILE_NOT_FOUND)
            e = ERROR_SUCCESS;
    }
    if (e && e != ERROR_FILE_NOT_FOUND)
        return e;
    if (wtg) {
        DWORD cs = 0, n = sizeof(cs);
        e = RegGetValueW(system.key, L"Select", L"Default", RRF_RT_REG_DWORD, nullptr, &cs, &n);
        if (e)
            return e;
        wchar_t path[80];
        swprintf(path, 80, L"ControlSet%03u\\Control", cs);
        e = RegOpenKeyExW(system.key, path, 0, KEY_SET_VALUE, &key);
        if (e)
            return e;
        DWORD one = 1, flags = 0x14;
        e = RegSetValueExW(key, L"PortableOperatingSystem", 0, REG_DWORD, reinterpret_cast<BYTE *>(&one), 4);
        if (!e)
            e = RegSetValueExW(key, L"BootDriverFlags", 0, REG_DWORD, reinterpret_cast<BYTE *>(&flags), 4);
        RegCloseKey(key);
    }
    return e == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : e;
}
LONG Post(const std::wstring &root, bool wtg) {
    Privileges privileges;
    if (!privileges.ok)
        return ERROR_PRIVILEGE_NOT_HELD;
    Hive system, software;
    LONG e = PostWork(root, wtg, system, software);
    LONG a = software.Close(), b = system.Close();
    return e ? e : (a ? a : b);
}

} // namespace
std::vector<WimImage> EnumerateWim(const std::wstring &path, WimResult &r) {
    r = {};
    r.stage = L"读取 WIM";
    Api a;
    if (!a.valid()) {
        r.hr = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        return {};
    }
    DWORD created = 0;
    Handle file{a.create(path.c_str(), GENERIC_READ, 3, a.versionMS > 0x60002 ? 0x20000000 : 0, 0, &created),
                a.close};
    if (!file.h || file.h == INVALID_HANDLE_VALUE) {
        r.hr = Err();
        return {};
    }
    wchar_t scratch[32768];
    if (!GetTempPathW(32768, scratch) || !a.temp(file.h, scratch)) {
        r.hr = Err();
        r.detail = L"无法为 WIM 元数据读取设置可写临时目录。";
        return {};
    }
    std::vector<WimImage> images;
    for (unsigned i = 1; i <= a.count(file.h); ++i) {
        Handle image{a.load(file.h, i), a.close};
        if (!image.h) {
            r.hr = Err();
            return {};
        }
        PVOID raw = nullptr;
        DWORD size = 0;
        if (!a.info(image.h, &raw, &size)) {
            r.hr = Err();
            return {};
        }
        if (!raw || size < 2 || size % 2 || size > 32 * 1024 * 1024) {
            if (raw)
                LocalFree(raw);
            r.hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            return {};
        }
        size_t chars = size / 2;
        auto text = static_cast<wchar_t *>(raw);
        while (chars && text[chars - 1] == 0)
            --chars;
        Xml xml(text, chars);
        LocalFree(raw);
        if (!xml.doc) {
            r.hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            r.detail = L"WIM 元数据 XML 无效。";
            return {};
        }
        WimImage x;
        x.index = i;
        x.name = xml.Get(L"/IMAGE/NAME");
        x.description = xml.Get(L"/IMAGE/DESCRIPTION");
        x.architecture = xml.Get(L"/IMAGE/WINDOWS/ARCH");
        x.major = Number(xml.Get(L"/IMAGE/WINDOWS/VERSION/MAJOR"));
        x.minor = Number(xml.Get(L"/IMAGE/WINDOWS/VERSION/MINOR"));
        x.build = Number(xml.Get(L"/IMAGE/WINDOWS/VERSION/BUILD"));
        x.revision = Number(xml.Get(L"/IMAGE/WINDOWS/VERSION/SPBUILD"));
        x.edition = xml.Get(L"/IMAGE/WINDOWS/EDITIONID");
        x.installationType = xml.Get(L"/IMAGE/WINDOWS/INSTALLATIONTYPE");
        x.languages = xml.All(L"/IMAGE/WINDOWS/LANGUAGES/LANGUAGE");
        try {
            x.totalBytes = std::stoull(xml.Get(L"/IMAGE/TOTALBYTES"));
        } catch (...) {
        }
        images.push_back(x);
    }
    r.hr = S_OK;
    return images;
}
WimResult ApplyWim(const WimOptions &o, std::atomic_bool &cancel, const WimProgress &progress) {
    WimResult r;
    r.stage = L"验证参数";
    auto root = Full(o.destination), source = Full(o.source);
    auto fail = [&](HRESULT e, const wchar_t *text) {
        r.hr = e;
        r.detail = text;
        return r;
    };
    if (root.size() != 3 || root[1] != L':' || root[2] != L'\\' || source.empty() || !o.imageIndex ||
        Lower(fs::path(source).extension().wstring()) != L".wim")
        return fail(E_INVALIDARG, L"只接受 WIM 文件和盘符根目录目标，例如 E:\\。");
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"))
        return fail(E_NOTIMPL, L"Wine 环境只允许读取元数据和执行内存自测，禁止释放映像。");
    MaintenanceLock operationLock;
    if (operationLock.Result() != S_OK)
        return fail(operationLock.Result(),
                    L"已有 ADism 维护任务或上次任务异常退出，未启动释放。请先核对系统状态。");
    if (cancel.load()) {
        r.cancelled = true;
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"开始前已取消，尚未修改目标。");
    }
    std::wstring guardDetail;
    HRESULT guard = ValidateDeploymentDisk(root, guardDetail);
    if (guard != S_OK) {
        r.detail = guardDetail;
        r.hr = guard;
        return r;
    }
    guard = ValidateEmptyDestination(root, guardDetail);
    if (guard != S_OK) {
        r.detail = guardDetail;
        r.hr = guard;
        return r;
    }

    wchar_t win[MAX_PATH];
    if (!GetWindowsDirectoryW(win, MAX_PATH))
        return fail(Err(), L"无法确定在线 Windows 路径。");
    std::wstring targetIdentity, windowsIdentity, sourceIdentity;
    if (!RealLocalDrive(root) || !VolumeIdentity(root, targetIdentity) ||
        !VolumeIdentity(win, windowsIdentity) || !VolumeIdentity(source, sourceIdentity))
        return fail(E_INVALIDARG, L"无法可靠识别本地卷；不支持 SUBST、网络盘或非实际卷盘符。");
    if (targetIdentity == windowsIdentity || sourceIdentity == targetIdentity)
        return fail(E_INVALIDARG, L"目标不能与在线 Windows 或源映像位于同一真实卷（包括盘符别名）。");
    if (Within(win, root) || Within(source, root) || ReparseAncestor(root) || ReparseAncestor(source))
        return fail(E_INVALIDARG, L"目标不能是在线系统卷，源不能位于目标内，也不能经重解析路径访问。");
    struct FilePin {
        HANDLE handle = INVALID_HANDLE_VALUE;
        ~FilePin() {
            if (handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
        }
    } pin;
    pin.handle =
        CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pin.handle == INVALID_HANDLE_VALUE)
        return fail(Err(), L"无法保持源映像只读且不可替换。");
    WimResult catalog;
    auto images = EnumerateWim(source, catalog);
    if (catalog.hr != S_OK)
        return catalog;
    if (!o.imageIndex || o.imageIndex > images.size())
        return fail(E_INVALIDARG, L"映像序号不存在。");
    auto image = images[o.imageIndex - 1];
    if (image.architecture != L"9")
        return fail(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), L"当前发布版仅支持 x64 Windows 映像。");
    if (o.windowsToGo && (image.major < 6 || (image.major == 6 && image.minor < 2)))
        return fail(E_INVALIDARG, L"WindowsToGo 需要 Windows 6.2 或更新映像。");
    if (o.addBoot) {
        auto bootCheck = ValidateBoot(o);
        if (bootCheck.hr != S_OK)
            return bootCheck;
    }
    Api a;
    if (!a.valid())
        return fail(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND), L"系统 WIMGAPI 不完整。");
    Context context{&cancel, &progress, root};
    ImageSession session(a, context);
    wchar_t scratch[32768];
    if (!GetTempPathW(32768, scratch) || !session.Prepare(source, o.imageIndex, scratch))
        return fail(Err(), L"打开、加载或注册 WIM 失败。");
    // Do not migrate or replace user data. Keep the WIM pinned through post-work.
    std::wstring currentIdentity;
    if (!VolumeIdentity(root, currentIdentity) || currentIdentity != targetIdentity)
        return fail(E_ACCESSDENIED, L"执行前目标卷身份变化，未执行释放。");
    guard = ValidateEmptyDestination(root, guardDetail);
    if (guard != S_OK) {
        r.hr = guard;
        r.detail = guardDetail;
        return r;
    }
    ULARGE_INTEGER available{};
    if (!GetDiskFreeSpaceExW(root.c_str(), &available, nullptr, nullptr))
        return fail(Err(), L"无法读取目标可用空间。");
    if (image.totalBytes && available.QuadPart < image.totalBytes)
        return fail(HRESULT_FROM_WIN32(ERROR_DISK_FULL), L"目标可用空间不足以容纳映像声明的文件总量。");
    if (cancel.load()) {
        r.cancelled = true;
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"已取消；尚未释放文件。");
    }
    r.stage = L"释放 WIM";
    r.partialChanges = true;
    BOOL ok = session.Apply(root);
    DWORD error = ok ? 0 : GetLastError();
    if (!ok) {
        r.cancelled = cancel.load() || error == ERROR_CANCELLED;
        return fail(
            HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE),
            L"释放未完成；可能已有部分文件，请检查目标并重新准备空白分区；本程序不会自动删除已释放的文件。");
    }
    if (context.threw)
        return fail(E_UNEXPECTED, L"映像已释放，但进度回调失败；已停止后处理，保留部分完成状态。");
    if (cancel.load()) {
        r.cancelled = true;
        return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED),
                    L"映像已释放，但在后处理前取消；未执行注册表或引导写入。");
    }
    r.stage = L"离线注册表后处理";
    if (!VolumeIdentity(root, currentIdentity) || currentIdentity != targetIdentity)
        return fail(E_ACCESSDENIED, L"释放后目标身份变化，未执行后处理。");
    if (!OrdinaryPath(root + L"Windows\\System32\\config\\SYSTEM") ||
        !OrdinaryPath(root + L"Windows\\System32\\config\\SOFTWARE"))
        return fail(E_ACCESSDENIED, L"离线注册表路径无效或经过重解析点，未执行后处理。");
    LONG e = Post(root, o.windowsToGo);
    if (e)
        return fail(HRESULT_FROM_WIN32(e), L"映像已经释放，但盘符映射或 WindowsToGo 后处理失败。");
    if (o.addBoot) {
        if (cancel.load()) {
            r.cancelled = true;
            return fail(HRESULT_FROM_WIN32(ERROR_CANCELLED), L"后处理完成后取消；尚未写入引导。");
        }
        WimOptions boot = o;
        boot.destination = root;
        auto b = WriteBoot(boot, progress);
        if (b.hr != S_OK) {
            b.partialChanges = true;
            return b;
        }
    }
    r.hr = S_OK;
    r.stage = L"完成";
    r.detail = L"映像释放及所选后处理完成。";
    r.partialChanges = false;
    return r;
}
int WimSelfTest() {
    const wchar_t *testXml = L"<IMAGE><NAME>A &amp; B &#x4e2d;</NAME></IMAGE>";
    Xml xml(testXml, wcslen(testXml));
    if (!xml.doc || xml.Get(L"/IMAGE/NAME") != L"A & B 中")
        return 1;
    std::wstring bomXml = L"\ufeff" + std::wstring(testXml);
    Xml withBom(bomXml.c_str(), bomXml.size());
    if (!withBom.doc || withBom.Get(L"/IMAGE/NAME") != L"A & B 中")
        return 6;
    if (!Within(L"E:\\a.wim", L"E:\\") || Within(L"F:\\a.wim", L"E:\\"))
        return 2;
    if (Number(L"bad"))
        return 3;
    wchar_t bad[2] = {L'X', L'Y'};
    if (ValidRegistryString(bad, 4, 2) || ValidRegistryString(bad, 6, 2) || ValidRegistryString(bad, 3, 2))
        return 4;
    wchar_t good[2] = {L'X', 0};
    if (!ValidRegistryString(good, 4, 2))
        return 5;
    return LifecycleTest();
}
} // namespace servicing
