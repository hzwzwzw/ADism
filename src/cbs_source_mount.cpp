// SPDX-License-Identifier: GPL-3.0-only
#include "win_util.h"
#include "safety.h"
#include "cbs_source_mount.h"
#include <sddl.h>
#include <objbase.h>
#include <utility>
#include <new>
#include <cwchar>
namespace servicing {
namespace {
HRESULT LastErrorHr() {
    DWORD e = GetLastError();
    return HRESULT_FROM_WIN32(e ? e : ERROR_GEN_FAILURE);
}
std::wstring Join(const std::wstring &a, const wchar_t *b) {
    return a + (a.empty() || a.back() == L'\\' ? L"" : L"\\") + b;
}
constexpr DWORD kReadOnly = 0x200;
constexpr HRESULT kCancelled = HRESULT_FROM_WIN32(ERROR_CANCELLED);
} // namespace
struct OwnedRepairMount::Impl {
    HMODULE dll = nullptr;
    HANDLE file = nullptr, image = nullptr;
    HANDLE recoveredFile = nullptr, recoveredImage = nullptr;
    std::wstring root, mount, scratch, diagnostic, errorDetail;
    bool rootOwned = false, mountOwned = false, scratchOwned = false;
    bool mounted = false, mountAttempted = false, registered = false;
    std::atomic_bool callbackFailed{false}, callbackActive{false};
    std::atomic_bool *cancel = nullptr;
    std::function<void(int, const std::wstring &)> progress;
    HANDLE(WINAPI *create)(PCWSTR, DWORD, DWORD, DWORD, DWORD, PDWORD) = nullptr;
    HANDLE(WINAPI *load)(HANDLE, DWORD) = nullptr;
    BOOL(WINAPI *close)(HANDLE) = nullptr;
    BOOL(WINAPI *temp)(HANDLE, PCWSTR) = nullptr;
    DWORD(WINAPI *reg)(HANDLE, FARPROC, PVOID) = nullptr;
    BOOL(WINAPI *unreg)(HANDLE, FARPROC) = nullptr;
    BOOL(WINAPI *mountImage)(HANDLE, PCWSTR, DWORD) = nullptr;
    BOOL(WINAPI *getMounted)(PWSTR, DWORD, PHANDLE, PHANDLE) = nullptr;
    BOOL(WINAPI *unmountImage)(HANDLE, DWORD) = nullptr;
    BOOL(WINAPI *getMountInfo)(int, PDWORD, PVOID, DWORD, PDWORD) = nullptr;
    struct MountInfo0 {
        wchar_t wim[MAX_PATH], path[MAX_PATH];
        DWORD index;
        BOOL readWrite;
    };
    static_assert(sizeof(MountInfo0) == 1048, "WIM_MOUNT_INFO_LEVEL0 ABI");
    HRESULT ConfirmAbsent() {
        // c142011c alone only says a mounted-image handle could not be
        // obtained. Require independent filesystem AND mount-catalog absence.
        if (!mountOwned || !getMountInfo)
            return E_UNEXPECTED;
        DWORD attributes = GetFileAttributesW(mount.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
            return LastErrorHr();
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return HRESULT_FROM_WIN32(ERROR_BUSY);
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW(Join(mount, L"*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND)
                return LastErrorHr();
        } else {
            bool empty = true;
            do {
                if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L".."))
                    empty = false;
            } while (FindNextFileW(find, &data));
            DWORD error = GetLastError();
            FindClose(find);
            if (error != ERROR_NO_MORE_FILES)
                return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
            if (!empty)
                return HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
        }
        DWORD count = 0, bytes = 0;
        BOOL result = getMountInfo(0, &count, nullptr, 0, &bytes);
        if (result && count == 0 && bytes == 0)
            return S_OK;
        if (!result && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return LastErrorHr();
        if (!bytes || bytes > 16 * 1024 * 1024)
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        std::unique_ptr<BYTE[]> buffer(new (std::nothrow) BYTE[bytes]);
        if (!buffer)
            return E_OUTOFMEMORY;
        DWORD returned = 0;
        if (!getMountInfo(0, &count, buffer.get(), bytes, &returned))
            return LastErrorHr();
        if (returned > bytes || count > returned / sizeof(MountInfo0))
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        auto *records = reinterpret_cast<const MountInfo0 *>(buffer.get());
        for (DWORD i = 0; i < count; ++i) {
            if (!wmemchr(records[i].path, 0, MAX_PATH))
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            if (!_wcsicmp(records[i].path, mount.c_str()))
                return HRESULT_FROM_WIN32(ERROR_BUSY);
        }
        return S_OK;
    }
    static DWORD CALLBACK Callback(DWORD message, WPARAM w, LPARAM, void *context) {
        auto &self = *static_cast<Impl *>(context);
        if (!self.callbackActive.load())
            return 0;
        // WIM_MSG_QUERY_ABORT / WIM_MSG_PROCESS: Microsoft specifies
        // WIM_MSG_ABORT_IMAGE (0xffffffff), not BOOL TRUE.
        if (message == 0x948e || message == 0x9479)
            return self.callbackFailed.load() || (self.cancel && self.cancel->load()) ? 0xffffffffu : 0u;
        if (message == 0x9478 && self.progress) {
            try {
                self.progress(static_cast<int>(w), L"正在只读挂载 CBS 修复来源");
            } catch (...) {
                self.callbackFailed = true;
            }
        }
        return 0;
    }
    bool Report(const std::wstring &text) {
        try {
            if (progress)
                progress(-1, text);
            return true;
        } catch (...) {
            callbackFailed = true;
            return false;
        }
    }
    HRESULT RemoveOwned(std::wstring &path, bool &owned) {
        if (!owned)
            return S_OK;
        // Never enumerate/delete contents: especially never recurse into a mount.
        if (!RemoveDirectoryW(path.c_str()))
            return LastErrorHr();
        owned = false;
        return S_OK;
    }
    HRESULT Close() {
        callbackActive = false;
        if (registered) {
            if (!unreg(file, FunctionPointer<FARPROC>(&Callback)))
                return LastErrorHr();
            registered = false;
        }
        // A failed mount call can still leave a registered mount. Query only our
        // own fresh path; never discover/adopt/unmount any other mount location.
        if (mountAttempted && !mounted) {
            if (getMounted(mount.data(), kReadOnly, &recoveredFile, &recoveredImage))
                mounted = true;
            else {
                DWORD error = GetLastError();
                // Only these explicit absence errors establish no mount exists.
                if (error == 0xc142011cu) {
                    HRESULT absent = ConfirmAbsent();
                    if (absent != S_OK)
                        return absent;
                } else if (error != ERROR_NOT_FOUND && error != ERROR_FILE_NOT_FOUND &&
                           error != ERROR_PATH_NOT_FOUND)
                    return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
                mountAttempted = false;
            }
        }
        if (mounted) {
            HANDLE active = recoveredImage ? recoveredImage : image;
            if (!active)
                return E_UNEXPECTED;
            // Progress failure must never prevent unmount/cleanup, nor is an
            // existing cancellation flag consulted during this phase.
            try {
                if (progress)
                    progress(-1, L"正在卸载只读修复来源：" + mount);
            } catch (...) {
            }
            if (!unmountImage(active, 0))
                return LastErrorHr();
            mounted = false;
            mountAttempted = false;
        }
        auto release = [&](HANDLE &handle) -> HRESULT {
            if (!handle || handle == INVALID_HANDLE_VALUE) {
                handle = nullptr;
                return S_OK;
            }
            if (!close(handle))
                return LastErrorHr();
            handle = nullptr;
            return S_OK;
        };
        HRESULT hr = release(recoveredImage);
        if (hr != S_OK)
            return hr;
        hr = release(recoveredFile);
        if (hr != S_OK)
            return hr;
        hr = release(image);
        if (hr != S_OK)
            return hr;
        hr = release(file);
        if (hr != S_OK)
            return hr;
        if (dll) {
            if (!FreeLibrary(dll))
                return LastErrorHr();
            dll = nullptr;
        }
        hr = RemoveOwned(mount, mountOwned);
        if (hr != S_OK)
            return hr;
        hr = RemoveOwned(scratch, scratchOwned);
        if (hr != S_OK)
            return hr;
        hr = RemoveOwned(root, rootOwned);
        if (hr != S_OK)
            return hr;
        root.clear();
        mount.clear();
        scratch.clear();
        diagnostic.clear();
        progress = {};
        cancel = nullptr;
        return S_OK;
    }
};
OwnedRepairMount::OwnedRepairMount() : impl_(new Impl) {}
OwnedRepairMount::~OwnedRepairMount() {
    // Caller explicitly observes Close's HRESULT. If final cleanup still fails,
    // retain handles/context until worker exit instead of losing a live mount
    // or callback context. No global cleanup, forced unmount, or recursive delete.
    if (impl_ && impl_->Close() != S_OK)
        impl_.release();
}
const std::wstring &OwnedRepairMount::Path() const {
    return impl_->diagnostic;
}
std::wstring OwnedRepairMount::Windows() const {
    return impl_->mounted ? Join(impl_->mount, L"Windows") : std::wstring{};
}
const std::wstring &OwnedRepairMount::ErrorDetail() const {
    return impl_->errorDetail;
}
HRESULT OwnedRepairMount::Close() {
    return impl_->Close();
}
HRESULT OwnedRepairMount::Open(const std::wstring &wim, unsigned index, std::atomic_bool &cancel,
                               const std::function<void(int, const std::wstring &)> &progress,
                               const std::wstring &workRoot) {
    auto &s = *impl_;
    if (s.rootOwned || s.dll || s.file || s.image || s.mounted)
        return HRESULT_FROM_WIN32(ERROR_BUSY);
    if (wim.empty() || !index)
        return E_INVALIDARG;
    if (cancel.load())
        return kCancelled;
    s.cancel = &cancel;
    s.progress = progress;
    s.callbackFailed = false;
    s.errorDetail.clear();
    const wchar_t *stage = L"验证工作分区";
    auto fail = [&](HRESULT primary) {
        wchar_t code[16]{};
        swprintf(code, 16, L"0x%08X", unsigned(primary));
        s.errorDetail = std::wstring(stage) + L"失败：" + code;
        if (!s.root.empty())
            s.errorDetail += L"；挂载目录=" + s.mount + L"；临时目录=" + s.scratch;
        s.Report(s.errorDetail);
        s.callbackActive = false;
        HRESULT cleanup = s.Close();
        if (cleanup != S_OK) {
            swprintf(code, 16, L"0x%08X", unsigned(cleanup));
            s.errorDetail += L"；清理失败：" + std::wstring(code);
        }
        return cleanup == S_OK ? primary : cleanup;
    };
    std::wstring base = workRoot;
    if (base.empty()) {
        wchar_t windows[32768]{};
        UINT n = GetWindowsDirectoryW(windows, 32768);
        if (!n || n >= 32768)
            return fail(E_INVALIDARG);
        base = std::wstring(windows, 3);
    }
    LocalRoot volume;
    HRESULT inspect = InspectRoot(base, volume);
    if (inspect != S_OK)
        return fail(inspect);
    if (_wcsicmp(volume.filesystem.c_str(), L"NTFS"))
        return fail(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED));
    if (volume.readOnly)
        return fail(E_ACCESSDENIED);
    if (!s.Report(L"修复源工作分区：" + volume.root + L"；卷=" + volume.volume + L"；文件系统=NTFS"))
        return fail(E_FAIL);
    stage = L"创建工作目录标识";
    GUID id{};
    HRESULT hr = CoCreateGuid(&id);
    if (hr != S_OK)
        return fail(hr);
    wchar_t guid[40];
    if (!StringFromGUID2(id, guid, 40))
        return fail(E_FAIL);
    s.root = Join(volume.root, (L"ADism-RepairSource-" + std::wstring(guid)).c_str());
    s.mount = Join(s.root, L"Mount");
    s.scratch = Join(s.root, L"Scratch");
    s.diagnostic = s.root;
    // WIMMountImageHandle only supports mount paths up to MAX_PATH.
    if (s.mount.size() >= MAX_PATH || s.scratch.size() >= MAX_PATH)
        return fail(HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE));
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                              SDDL_REVISION_1, &descriptor, nullptr))
        return fail(LastErrorHr());
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
    stage = L"创建独占工作目录";
    BOOL made = CreateDirectoryW(s.root.c_str(), &attributes);
    DWORD error = GetLastError();
    LocalFree(descriptor);
    if (!made)
        return fail(HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE));
    s.rootOwned = true;
    stage = L"创建挂载目录";
    if (!CreateDirectoryW(s.mount.c_str(), nullptr))
        return fail(LastErrorHr());
    s.mountOwned = true;
    stage = L"创建临时工作目录";
    if (!CreateDirectoryW(s.scratch.c_str(), nullptr))
        return fail(LastErrorHr());
    s.scratchOwned = true;
    if (!s.Report(L"正在准备独占的只读修复来源挂载：" + s.mount))
        return fail(E_FAIL);
    if (cancel.load())
        return fail(kCancelled);
    stage = L"加载系统 WIMGAPI";
    s.dll = LoadLibraryExW(L"wimgapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!s.dll)
        return fail(LastErrorHr());
#define GET(field, name) s.field = LoadFunction<decltype(s.field)>(s.dll, name)
    GET(create, "WIMCreateFile");
    GET(load, "WIMLoadImage");
    GET(close, "WIMCloseHandle");
    GET(temp, "WIMSetTemporaryPath");
    GET(reg, "WIMRegisterMessageCallback");
    GET(unreg, "WIMUnregisterMessageCallback");
    GET(mountImage, "WIMMountImageHandle");
    GET(getMounted, "WIMGetMountedImageHandle");
    GET(unmountImage, "WIMUnmountImageHandle");
    GET(getMountInfo, "WIMGetMountedImageInfo");
#undef GET
    if (!s.create || !s.load || !s.close || !s.temp || !s.reg || !s.unreg || !s.mountImage || !s.getMounted ||
        !s.unmountImage || !s.getMountInfo)
        return fail(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    stage = L"打开修复 WIM";
    DWORD disposition = 0;
    s.file = s.create(wim.c_str(), GENERIC_READ | GENERIC_EXECUTE, OPEN_EXISTING, 0, 0, &disposition);
    if (!s.file || s.file == INVALID_HANDLE_VALUE)
        return fail(LastErrorHr());
    stage = L"设置 WIM 临时目录";
    if (!s.temp(s.file, s.scratch.c_str()))
        return fail(LastErrorHr());
    stage = L"读取 WIM 映像索引";
    s.image = s.load(s.file, index);
    if (!s.image)
        return fail(LastErrorHr());
    s.callbackActive = true;
    if (s.reg(s.file, FunctionPointer<FARPROC>(&Impl::Callback), &s) == 0xffffffffu)
        return fail(LastErrorHr());
    s.registered = true;
    if (cancel.load())
        return fail(kCancelled);
    stage = L"只读挂载 WIM";
    s.mountAttempted = true;
    BOOL success = s.mountImage(s.image, s.mount.c_str(), kReadOnly);
    error = GetLastError();
    if (success)
        s.mounted = true;
    s.callbackActive = false;
    if (!s.unreg(s.file, FunctionPointer<FARPROC>(&Impl::Callback)))
        return fail(LastErrorHr());
    s.registered = false;
    if (s.callbackFailed.load())
        return fail(E_FAIL);
    if (cancel.load())
        return fail(kCancelled);
    if (!success)
        return fail(HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE));
    if (!s.Report(L"CBS 只读修复来源已挂载：" + Windows()))
        return fail(E_FAIL);
    return S_OK;
}
} // namespace servicing
