// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/naive/socks5_udp_packet.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/numerics/byte_conversions.h"
#include "base/strings/string_view_util.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"

namespace net {

namespace {

constexpr uint8_t kSocks5UdpReserved = 0x00;
constexpr uint8_t kSocks5UdpNoFragment = 0x00;
constexpr uint8_t kAddressTypeIPv4 = 0x01;
constexpr uint8_t kAddressTypeDomain = 0x03;
constexpr uint8_t kAddressTypeIPv6 = 0x04;
constexpr size_t kHeaderPrefixSize = 4;
constexpr size_t kPortSize = 2;
constexpr size_t kMaxUdpPacketSize = std::numeric_limits<uint16_t>::max();

}  // namespace

std::optional<Socks5UdpPacket> ParseSocks5UdpPacket(std::string_view packet) {
  if (packet.size() < kHeaderPrefixSize + kPortSize ||
      packet.size() > kMaxUdpPacketSize) {
    return std::nullopt;
  }

  const auto bytes = base::as_byte_span(packet);
  if (bytes[0] != kSocks5UdpReserved || bytes[1] != kSocks5UdpReserved ||
      bytes[2] != kSocks5UdpNoFragment) {
    return std::nullopt;
  }

  size_t address_offset = kHeaderPrefixSize;
  size_t address_size = 0;
  const uint8_t address_type = static_cast<uint8_t>(bytes[3]);
  switch (address_type) {
    case kAddressTypeIPv4:
      address_size = IPAddress::kIPv4AddressSize;
      break;
    case kAddressTypeIPv6:
      address_size = IPAddress::kIPv6AddressSize;
      break;
    case kAddressTypeDomain:
      if (packet.size() < kHeaderPrefixSize + 1 + kPortSize) {
        return std::nullopt;
      }
      address_size = static_cast<uint8_t>(bytes[address_offset]);
      if (address_size == 0) {
        return std::nullopt;
      }
      ++address_offset;
      break;
    default:
      return std::nullopt;
  }

  if (packet.size() < address_offset + address_size + kPortSize) {
    return std::nullopt;
  }

  size_t port_offset = address_offset + address_size;
  uint16_t port = base::U16FromBigEndian(
      base::as_byte_span(packet).subspan(port_offset).first<2>());
  if (port == 0) {
    return std::nullopt;
  }

  HostPortPair destination;
  if (address_type == kAddressTypeDomain) {
    destination = HostPortPair(
        std::string(packet.substr(address_offset, address_size)), port);
  } else {
    IPAddress address(bytes.subspan(address_offset, address_size));
    destination = HostPortPair::FromIPEndPoint(IPEndPoint(address, port));
  }

  return Socks5UdpPacket{
      std::move(destination),
      std::string(packet.substr(port_offset + kPortSize)),
  };
}

std::optional<std::string> BuildSocks5UdpPacket(const HostPortPair& destination,
                                                std::string_view payload) {
  if (destination.port() == 0) {
    return std::nullopt;
  }
  const std::string& host = destination.host();
  IPAddress address;
  uint8_t address_type = kAddressTypeDomain;
  size_t encoded_address_size = 0;

  if (address.AssignFromIPLiteral(host)) {
    if (address.IsIPv4()) {
      address_type = kAddressTypeIPv4;
    } else {
      DCHECK(address.IsIPv6());
      address_type = kAddressTypeIPv6;
    }
    encoded_address_size = address.bytes().size();
  } else {
    if (host.empty() || host.size() > std::numeric_limits<uint8_t>::max()) {
      return std::nullopt;
    }
    encoded_address_size = 1 + host.size();
  }

  const size_t packet_size =
      kHeaderPrefixSize + encoded_address_size + kPortSize + payload.size();
  if (packet_size > kMaxUdpPacketSize) {
    return std::nullopt;
  }

  std::string packet;
  packet.reserve(packet_size);
  packet.push_back(kSocks5UdpReserved);
  packet.push_back(kSocks5UdpReserved);
  packet.push_back(kSocks5UdpNoFragment);
  packet.push_back(static_cast<char>(address_type));
  if (address_type == kAddressTypeDomain) {
    packet.push_back(static_cast<char>(host.size()));
    packet.append(host);
  } else {
    packet.append(reinterpret_cast<const char*>(address.bytes().data()),
                  address.bytes().size());
  }
  packet.push_back(static_cast<char>(destination.port() >> 8));
  packet.push_back(static_cast<char>(destination.port() & 0xff));
  packet.append(payload);
  return packet;
}

}  // namespace net
