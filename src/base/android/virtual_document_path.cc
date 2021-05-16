// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/virtual_document_path.h"

#include <optional>
#include <string_view>
#include <utility>

#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/android/jni_string.h"
#include "base/check.h"

namespace base::files_internal {

VirtualDocumentPath::VirtualDocumentPath(
    const base::android::JavaRef<jobject>& obj) {
  obj_.Reset(obj);
}

VirtualDocumentPath::VirtualDocumentPath(const VirtualDocumentPath& path) =
    default;
VirtualDocumentPath& VirtualDocumentPath::operator=(
    const VirtualDocumentPath& path) = default;

VirtualDocumentPath::~VirtualDocumentPath() = default;

std::optional<VirtualDocumentPath> VirtualDocumentPath::Parse(
    const std::string&) {
  return std::nullopt;
}

std::optional<std::string> VirtualDocumentPath::ResolveToContentUri() const {
  return std::nullopt;
}

base::expected<ResolvedDocument, base::File::Error>
VirtualDocumentPath::ResolveDocument() const {
  return base::unexpected(base::File::FILE_ERROR_FAILED);
}

std::string VirtualDocumentPath::ToString() const {
  return {};
}

bool VirtualDocumentPath::Mkdir(mode_t) const {
  return false;
}

bool VirtualDocumentPath::WriteFile(span<const uint8_t>) const {
  return false;
}

base::expected<std::string, base::File::Error>
VirtualDocumentPath::CreateDocument(std::string_view mime_type) const {
  return base::unexpected(base::File::FILE_ERROR_FAILED);
}

std::optional<std::pair<std::string, bool>> VirtualDocumentPath::CreateOrOpen(
    std::string_view) const {
  return std::nullopt;
}

}  // namespace base::files_internal

DEFINE_JNI(VirtualDocumentPath)
