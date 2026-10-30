// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <cstring>
namespace servicing {
// Windows x64 exposes function addresses through FARPROC. Preserve the ABI
// representation without converting incompatible function types by a C++ call.
template <class To, class From> To FunctionPointer(From address) noexcept {
    static_assert(sizeof(To) == sizeof(From), "Windows function pointer ABI");
    To result = nullptr;
    std::memcpy(&result, &address, sizeof(result));
    return result;
}
template <class F> F LoadFunction(HMODULE module, const char *name) noexcept {
    return FunctionPointer<F>(GetProcAddress(module, name));
}
} // namespace servicing
