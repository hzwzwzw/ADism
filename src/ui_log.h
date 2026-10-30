// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <memory>
#include <string>
#include <cstdint>
#include <vector>
#include <array>
namespace workbench {
enum class LogLevel { Info, Detail, Warning, Error };
std::wstring DisplayText(std::wstring text);
void StartLog(const std::wstring &path);
void Log(const std::wstring &text, bool brief = true, const std::wstring &scope = L"任务",
         LogLevel level = LogLevel::Info);
std::wstring LogText(bool full);
std::wstring LogPath();
uint64_t LogRevision();
struct LogGroup {
    std::wstring title;
    uint64_t total = 0;
    bool clipped = false;
    std::vector<std::wstring> rows;
};
std::vector<LogGroup> StructuredLog();
std::wstring StructuredLogText();
uint64_t FileLogOffset(const std::wstring &path);
class FileLogFollower {
    struct State;
    std::unique_ptr<State> state_;

  public:
    FileLogFollower(const std::wstring &path, uint64_t offset, const std::wstring &scope);
    ~FileLogFollower();
    FileLogFollower(const FileLogFollower &) = delete;
    FileLogFollower &operator=(const FileLogFollower &) = delete;
};
int LogSelfTest();
} // namespace workbench
