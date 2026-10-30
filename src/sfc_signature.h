// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <string>
namespace servicing {
HRESULT VerifySfcSignature(const std::wstring &path, HANDLE file, const std::wstring &systemDirectory,
                           std::wstring &evidence);
}
