// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_NAIVE_SOCKS5_UDP_PACKET_H_
#define NET_TOOLS_NAIVE_SOCKS5_UDP_PACKET_H_

#include <optional>
#include <string>
#include <string_view>

#include "net/base/host_port_pair.h"

namespace net {

struct Socks5UdpPacket {
  HostPortPair destination;
  std::string payload;
};

// Parses a SOCKS5 UDP request or response packet. Returns nullopt for malformed
// packets, unsupported address types, non-zero FRAG, or oversized fields.
std::optional<Socks5UdpPacket> ParseSocks5UdpPacket(std::string_view packet);

// Serializes a SOCKS5 UDP packet with RSV=0 and FRAG=0.
std::optional<std::string> BuildSocks5UdpPacket(const HostPortPair& destination,
                                                std::string_view payload);

}  // namespace net

#endif  // NET_TOOLS_NAIVE_SOCKS5_UDP_PACKET_H_
