// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "wim_backend.h"
namespace servicing {
WimResult ValidateBoot(const WimOptions &);
WimResult WriteBoot(const WimOptions &, const WimProgress &);
int BootSelfTest();
} // namespace servicing
