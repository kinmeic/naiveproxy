// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/connect_udp_helper.h"

#include <algorithm>
#include <optional>
#include <set>
#include <string>

#include "base/logging.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/proxy_chain.h"
#include "net/http/http_response_headers.h"
#include "net/http/structured_headers.h"
#include "net/third_party/uri_template/uri_template.h"
#include "third_party/abseil-cpp/absl/container/flat_hash_map.h"
#include "url/gurl.h"

namespace net {

namespace {

constexpr std::string_view kForbiddenTemplateOperators = "+#./;";
constexpr std::string_view kDefaultPathTemplate =
    "/.well-known/masque/udp/{target_host}/{target_port}/";

}  // namespace

GURL BuildConnectUdpUrl(const ProxyChain& proxy_chain,
                        size_t proxy_chain_index,
                        const HostPortPair& endpoint,
                        std::string_view path_template) {
  if (path_template.empty()) {
    path_template = kDefaultPathTemplate;
  }
  std::string path;
  std::set<std::string> vars_found;
  absl::flat_hash_map<std::string, std::string> parameters = {
      {"target_host", endpoint.host()},
      {"target_port", base::NumberToString(endpoint.port())},
  };
  if (!uri_template::Expand(std::string(path_template), parameters, &path,
                            &vars_found) ||
      !vars_found.contains("target_host") ||
      !vars_found.contains("target_port")) {
    DLOG(ERROR) << "Failed to expand CONNECT-UDP path template";
    return GURL();
  }
  const HostPortPair& proxy_authority =
      proxy_chain.GetProxyServer(proxy_chain_index).host_port_pair();
  GURL url(base::StrCat({"https://", proxy_authority.ToString(), path}));
  DLOG_IF(ERROR, !url.is_valid())
      << "CONNECT-UDP path template produced an invalid URL";
  return url;
}

bool IsValidConnectUdpPathTemplate(std::string_view path_template) {
  if (path_template.empty() || path_template.front() != '/' ||
      !std::ranges::all_of(path_template, [](unsigned char c) {
        // URI templates in configuration must contain visible ASCII only.
        return c >= 0x21 && c <= 0x7e;
      })) {
    return false;
  }

  for (size_t open = path_template.find('{'); open != std::string_view::npos;
       open = path_template.find('{', open + 1)) {
    const size_t close = path_template.find('}', open + 1);
    if (close == std::string_view::npos) {
      return false;
    }
    const std::string_view expression =
        path_template.substr(open + 1, close - open - 1);
    if (expression.empty() ||
        kForbiddenTemplateOperators.contains(expression.front()) ||
        expression.find_first_of("*:") != std::string_view::npos) {
      return false;
    }
  }

  std::string expanded;
  std::set<std::string> vars_found;
  absl::flat_hash_map<std::string, std::string> parameters = {
      {"target_host", "2001:db8::42"},
      {"target_port", "65535"},
  };
  if (!uri_template::Expand(std::string(path_template), parameters, &expanded,
                            &vars_found) ||
      !vars_found.contains("target_host") ||
      !vars_found.contains("target_port")) {
    return false;
  }

  GURL url(base::StrCat({"https://example.test", expanded}));
  return url.is_valid() && url.host() == "example.test" &&
         url.path() == expanded && !url.has_query() && !url.has_ref();
}

bool IsSuccessfulConnectUdpResponse(
    const HttpResponseHeaders& response_headers) {
  const int response_code = response_headers.response_code();
  // Non-2xx responses, notably a normal 407 authentication challenge, are
  // handled by the proxy socket state machine.
  if (response_code < 200 || response_code >= 300) {
    return false;
  }
  if (response_code == 204 || response_code == 205 || response_code == 206) {
    DLOG(WARNING) << "Rejecting CONNECT-UDP response with status "
                  << response_code;
    return false;
  }
  if (response_headers.HasHeader("content-length") ||
      response_headers.HasHeader("content-type") ||
      response_headers.HasHeader("transfer-encoding")) {
    DLOG(WARNING)
        << "Rejecting CONNECT-UDP response with representation headers";
    return false;
  }

  // A successful CONNECT-UDP response must opt into the Capsule Protocol.
  // Without this header, the response cannot be used as a capsule stream.
  std::optional<std::string> capsule_protocol =
      response_headers.GetNormalizedHeader("capsule-protocol");
  if (!capsule_protocol.has_value()) {
    DLOG(WARNING) << "Rejecting CONNECT-UDP response without Capsule-Protocol";
    return false;
  }
  std::optional<structured_headers::ParameterizedItem> item =
      structured_headers::ParseItem(*capsule_protocol);
  if (!item.has_value() || !item->item.is_boolean() ||
      !item->item.GetBoolean()) {
    DLOG(WARNING)
        << "Rejecting CONNECT-UDP response with invalid Capsule-Protocol";
    return false;
  }
  return true;
}

}  // namespace net
