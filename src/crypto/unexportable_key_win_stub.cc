// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/unexportable_key_win.h"

namespace crypto {

ScopedNCryptKey DuplicatePlatformKeyHandle(const UnexportableSigningKey&) {
  return {};
}

std::unique_ptr<UnexportableKeyProvider> GetUnexportableKeyProviderWin() {
  return nullptr;
}

std::unique_ptr<UnexportableKeyProvider>
GetMicrosoftSoftwareUnexportableKeyProviderWin() {
  return nullptr;
}

}  // namespace crypto
