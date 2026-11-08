// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_CONNECT_UDP_HELPER_H_
#define NET_HTTP_CONNECT_UDP_HELPER_H_

#include <stddef.h>

#include <string_view>

#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "url/gurl.h"

namespace net {

class ProxyChain;
class HttpResponseHeaders;

NET_EXPORT GURL BuildConnectUdpUrl(const ProxyChain& proxy_chain,
                                   size_t proxy_chain_index,
                                   const HostPortPair& endpoint,
                                   std::string_view path_template = {});

NET_EXPORT bool IsValidConnectUdpPathTemplate(std::string_view path_template);

NET_EXPORT bool IsSuccessfulConnectUdpResponse(
    const HttpResponseHeaders& response_headers);

}  // namespace net

#endif  // NET_HTTP_CONNECT_UDP_HELPER_H_
