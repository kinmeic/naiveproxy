// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/naive/naive_udp_association.h"

#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/string_view_util.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/socket/stream_socket.h"
#include "net/socket/udp_server_socket.h"
#include "net/tools/naive/naive_connection.h"
#include "net/tools/naive/naive_proxy.h"
#include "net/tools/naive/socks5_udp_packet.h"

namespace net {
namespace {
constexpr int kControlBufferSize = 1024;
constexpr int kUdpBufferSize = 65535;
}  // namespace

NaiveUdpAssociation::NaiveUdpAssociation(
    NaiveProxy* owner,
    std::unique_ptr<StreamSocket> control_socket,
    std::unique_ptr<UDPServerSocket> udp_socket,
    const HostPortPair& requested_client_endpoint,
    base::TimeDelta connect_udp_timeout,
    base::TimeDelta tunnel_timeout,
    base::TimeDelta association_idle_timeout,
    const NaiveUdpAssociationLimits& limits)
    : owner_(owner),
      control_socket_(std::move(control_socket)),
      udp_socket_(std::move(udp_socket)),
      requested_client_endpoint_(requested_client_endpoint),
      connect_udp_timeout_(connect_udp_timeout),
      tunnel_timeout_(tunnel_timeout),
      association_idle_timeout_(association_idle_timeout),
      limits_(limits) {
  DCHECK(owner_);
  DCHECK(control_socket_);
  DCHECK(udp_socket_);
  DCHECK_GT(connect_udp_timeout_, base::TimeDelta());
  DCHECK_GT(tunnel_timeout_, base::TimeDelta());
  DCHECK_GT(association_idle_timeout_, base::TimeDelta());
}

NaiveUdpAssociation::~NaiveUdpAssociation() {
  if (control_socket_) {
    control_socket_->Disconnect();
  }
  if (udp_socket_) {
    udp_socket_->Close();
  }
}

void NaiveUdpAssociation::Start() {
  IPEndPoint control_peer_address;
  int rv = control_socket_->GetPeerAddress(&control_peer_address);
  if (rv != OK || !control_peer_address.address().IsValid()) {
    owner_->CloseUdpAssociation(this, rv == OK ? ERR_ADDRESS_INVALID : rv);
    return;
  }
  client_ip_address_ = control_peer_address.address();
  IPAddress requested_address;
  if (requested_address.AssignFromIPLiteral(
          requested_client_endpoint_.host()) &&
      !requested_address.IsZero() && requested_address != client_ip_address_) {
    owner_->CloseUdpAssociation(this, ERR_ADDRESS_INVALID);
    return;
  }
  if (requested_client_endpoint_.port() != 0) {
    client_udp_endpoint_ =
        IPEndPoint(client_ip_address_, requested_client_endpoint_.port());
  }
  ResetIdleTimer();
  DoControlRead();
  DoUdpRead();
}

void NaiveUdpAssociation::CloseTargetFlows() {
  // Synchronous socket completions are posted to avoid recursive dispatch.
  // Cancel those tasks, as well as outstanding socket callbacks, before
  // clearing the state they refer to.
  weak_ptr_factory_.InvalidateWeakPtrs();
  flow_cleanup_timer_.Stop();
  idle_timer_.Stop();
  if (control_socket_) {
    control_socket_->Disconnect();
  }
  if (udp_socket_) {
    udp_socket_->Close();
  }
  udp_send_queue_.clear();
  udp_send_queue_bytes_ = 0;
  udp_send_pending_ = false;
  udp_send_buf_ = nullptr;
  while (!flows_.empty()) {
    RemoveFlow(flows_.begin(), OK);
  }
}

void NaiveUdpAssociation::OnFlowCleanupTimer() {
  const base::TimeTicks now = base::TimeTicks::Now();
  for (auto it = flows_.begin(); it != flows_.end();) {
    if (now - it->second.last_used < connect_udp_timeout_ &&
        now - it->second.created_at < tunnel_timeout_) {
      ++it;
      continue;
    }
    auto expired = it++;
    RemoveFlow(expired, OK);
  }
  if (flows_.empty()) {
    flow_cleanup_timer_.Stop();
    return;
  }

  auto it = flows_.begin();
  base::TimeTicks earliest_deadline =
      std::min(it->second.last_used + connect_udp_timeout_,
               it->second.created_at + tunnel_timeout_);
  for (++it; it != flows_.end(); ++it) {
    earliest_deadline = std::min({earliest_deadline,
                                  it->second.last_used + connect_udp_timeout_,
                                  it->second.created_at + tunnel_timeout_});
  }

  // Keeping an already scheduled earlier wakeup is safe: activity can move a
  // flow's deadline later, and that wakeup will simply compute the next exact
  // deadline. Restart only when a newly added flow expires sooner.
  if (flow_cleanup_timer_.IsRunning() &&
      flow_cleanup_timer_.desired_run_time() <= earliest_deadline) {
    return;
  }

  base::TimeDelta delay = earliest_deadline - base::TimeTicks::Now();
  flow_cleanup_timer_.Start(
      FROM_HERE, std::max(delay, base::TimeDelta()),
      base::BindOnce(&NaiveUdpAssociation::OnFlowCleanupTimer,
                     weak_ptr_factory_.GetWeakPtr()));
}

void NaiveUdpAssociation::DoControlRead() {
  if (!control_read_buf_) {
    control_read_buf_ =
        base::MakeRefCounted<IOBufferWithSize>(kControlBufferSize);
  }
  int rv = control_socket_->Read(
      control_read_buf_.get(), kControlBufferSize,
      base::BindOnce(&NaiveUdpAssociation::OnControlReadComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveUdpAssociation::OnControlReadComplete,
                                  weak_ptr_factory_.GetWeakPtr(), rv));
  }
}

void NaiveUdpAssociation::OnControlReadComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK_LE(result, kControlBufferSize);
  if (result <= 0) {
    owner_->CloseUdpAssociation(
        this, result == 0 || result == ERR_CONNECTION_CLOSED ? OK : result);
    return;
  }
  ResetIdleTimer();
  DoControlRead();
}

void NaiveUdpAssociation::DoUdpRead() {
  if (!udp_read_buf_) {
    udp_read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kUdpBufferSize);
  }
  int rv = udp_socket_->RecvFrom(
      udp_read_buf_.get(), kUdpBufferSize, &udp_read_address_,
      base::BindOnce(&NaiveUdpAssociation::OnUdpReadComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveUdpAssociation::OnUdpReadComplete,
                                  weak_ptr_factory_.GetWeakPtr(), rv));
  }
}

void NaiveUdpAssociation::OnUdpReadComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK_LE(result, kUdpBufferSize);
  if (result == ERR_MSG_TOO_BIG) {
    DLOG(WARNING) << "Dropping oversized SOCKS5 UDP packet";
    DoUdpRead();
    return;
  }
  if (result < 0) {
    owner_->CloseUdpAssociation(this, result);
    return;
  }
  if (udp_read_address_.address() != client_ip_address_) {
    DLOG(WARNING) << "Dropping SOCKS5 UDP packet from "
                  << udp_read_address_.ToString()
                  << ": source address does not match TCP client "
                  << client_ip_address_.ToString();
  } else if (client_udp_endpoint_.has_value() &&
             udp_read_address_ != *client_udp_endpoint_) {
    DLOG(WARNING) << "Dropping SOCKS5 UDP packet from unexpected endpoint "
                  << udp_read_address_.ToString() << ", expected "
                  << client_udp_endpoint_->ToString();
  } else {
    std::string_view packet_data(udp_read_buf_->data(), result);
    std::optional<Socks5UdpPacket> packet = ParseSocks5UdpPacket(packet_data);
    if (packet.has_value()) {
      if (OnUdpPacket(packet->destination, std::move(packet->payload))) {
        if (!client_udp_endpoint_.has_value()) {
          client_udp_endpoint_ = udp_read_address_;
        }
        ResetIdleTimer();
      }
    } else {
      DLOG(WARNING) << "Dropping malformed SOCKS5 UDP packet from "
                    << udp_read_address_.ToString() << " length " << result;
    }
  }

  DoUdpRead();
}

bool NaiveUdpAssociation::OnUdpPacket(const HostPortPair& destination,
                                      std::string payload) {
  if (limits_.max_queued_bytes_per_flow != 0 &&
      payload.size() > limits_.max_queued_bytes_per_flow) {
    DLOG(WARNING) << "Dropping SOCKS5 UDP datagram for "
                  << destination.ToString()
                  << ": payload exceeds flow write queue byte limit";
    return false;
  }
  auto it = flows_.find(destination);
  if (it == flows_.end()) {
    if (limits_.max_target_flows != 0 &&
        flows_.size() >= limits_.max_target_flows) {
      // Reclaim flows which have already reached their idle deadline before
      // applying admission control. Existing flows are never displaced for a
      // new target: CONNECT and CONNECT-UDP streams share Chromium's native
      // proxy-tunnel scheduler, so preempting a CONNECT-UDP stream here would
      // undermine its stable flow ordering and cause retry-driven thrashing.
      OnFlowCleanupTimer();
      if (flows_.size() >= limits_.max_target_flows) {
        DLOG(WARNING) << "Dropping SOCKS5 UDP datagram for new target "
                      << destination.ToString()
                      << ": association target flow limit reached";
        return false;
      }
    }
    TargetFlow flow;
    flow.generation = next_flow_generation_++;
    auto [new_it, inserted] = flows_.emplace(destination, std::move(flow));
    DCHECK(inserted);
    it = new_it;
    auto generation_result =
        flow_by_generation_.emplace(it->second.generation, it);
    DCHECK(generation_result.second);
    if (!QueueWrite(destination, it->second, std::move(payload))) {
      RemoveFlow(it, OK);
      return false;
    }
    if (!flow_cleanup_timer_.IsRunning()) {
      base::TimeTicks deadline =
          std::min(it->second.last_used + connect_udp_timeout_,
                   it->second.created_at + tunnel_timeout_);
      base::TimeDelta delay = deadline - base::TimeTicks::Now();
      flow_cleanup_timer_.Start(
          FROM_HERE, std::max(delay, base::TimeDelta()),
          base::BindOnce(&NaiveUdpAssociation::OnFlowCleanupTimer,
                         weak_ptr_factory_.GetWeakPtr()));
    }
    DoFlowConnect(destination, it->second);
    return true;
  }

  if (!QueueWrite(destination, it->second, std::move(payload))) {
    return false;
  }
  return true;
}

NaiveUdpAssociation::FlowMap::iterator NaiveUdpAssociation::FindFlow(
    uint64_t generation) {
  auto it = flow_by_generation_.find(generation);
  return it == flow_by_generation_.end() ? flows_.end() : it->second;
}

void NaiveUdpAssociation::RemoveFlow(FlowMap::iterator flow, int reason) {
  DCHECK(flow != flows_.end());
  const uint64_t generation = flow->second.generation;
  const std::optional<unsigned int> connection_id = flow->second.connection_id;
  const size_t erased = flow_by_generation_.erase(generation);
  DCHECK_EQ(erased, 1u);
  flows_.erase(flow);
  if (connection_id.has_value()) {
    owner_->Close(*connection_id, reason);
  }
}

void NaiveUdpAssociation::DoFlowConnect(const HostPortPair& target,
                                        TargetFlow& flow) {
  DCHECK(!flow.connection_id.has_value());
  DCHECK(!flow.connected);
  NaiveConnection* connection = owner_->CreateDatagramConnection(target);
  if (!connection) {
    CloseFlow(target, ERR_INSUFFICIENT_RESOURCES);
    return;
  }
  flow.connection_id = connection->id();
  int rv = connection->ConnectServer(
      base::BindOnce(&NaiveUdpAssociation::OnFlowConnectComplete,
                     weak_ptr_factory_.GetWeakPtr(), flow.generation));
  if (rv != ERR_IO_PENDING) {
    OnFlowConnectComplete(flow.generation, rv);
  }
}

void NaiveUdpAssociation::OnFlowConnectComplete(uint64_t generation,
                                                int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  auto it = FindFlow(generation);
  if (it == flows_.end()) {
    return;
  }
  const HostPortPair& target = it->first;
  TargetFlow& flow = it->second;
  DCHECK(flow.connection_id.has_value());
  DCHECK(!flow.connected);
  if (result != OK) {
    CloseFlow(target, result);
    return;
  }
  flow.connected = true;
  DoNextFlowWrite(target, flow);
  it = FindFlow(generation);
  if (it != flows_.end()) {
    DoFlowRead(it->first, it->second);
  }
}

bool NaiveUdpAssociation::QueueWrite(const HostPortPair& target,
                                     TargetFlow& flow,
                                     std::string payload) {
  DCHECK(limits_.max_queued_bytes_per_flow == 0 ||
         payload.size() <= limits_.max_queued_bytes_per_flow);
  flow.last_used = base::TimeTicks::Now();
  if (flow.connected && !flow.write_pending && flow.write_queue.empty()) {
    DoFlowWrite(target, flow, std::move(payload));
    return true;
  }

  // Once the outer reliable stream is flow-control blocked, retaining old
  // datagrams only increases head-of-line latency for the inner UDP flow.
  // Preserve the most recent datagrams instead. QUIC and other UDP protocols
  // can recover from the discarded packets at their own layer.
  bool discarded = false;
  while (!flow.write_queue.empty() &&
         ((limits_.max_queued_datagrams_per_flow != 0 &&
           flow.write_queue.size() >= limits_.max_queued_datagrams_per_flow) ||
          (limits_.max_queued_bytes_per_flow != 0 &&
           flow.write_queue_bytes >
               limits_.max_queued_bytes_per_flow - payload.size()))) {
    DCHECK_GE(flow.write_queue_bytes, flow.write_queue.front().size());
    flow.write_queue_bytes -= flow.write_queue.front().size();
    flow.write_queue.pop_front();
    discarded = true;
  }
  if (discarded) {
    DLOG(WARNING) << "Discarding oldest SOCKS5 UDP datagrams for "
                  << target.ToString() << ": flow write queue is full";
  }
  flow.write_queue_bytes += payload.size();
  flow.write_queue.push_back(std::move(payload));
  if (flow.connected) {
    DoNextFlowWrite(target, flow);
  }
  return true;
}

void NaiveUdpAssociation::DoNextFlowWrite(const HostPortPair& target,
                                          TargetFlow& flow) {
  if (flow.write_pending || flow.write_queue.empty()) {
    return;
  }

  std::string payload = std::move(flow.write_queue.front());
  DCHECK_GE(flow.write_queue_bytes, payload.size());
  flow.write_queue_bytes -= payload.size();
  flow.write_queue.pop_front();
  DoFlowWrite(target, flow, std::move(payload));
}

void NaiveUdpAssociation::DoFlowWrite(const HostPortPair& target,
                                      TargetFlow& flow,
                                      std::string payload) {
  NaiveConnection* connection =
      flow.connection_id.has_value()
          ? owner_->FindConnection(*flow.connection_id)
          : nullptr;
  if (!connection) {
    CloseFlow(target, ERR_SOCKET_NOT_CONNECTED);
    return;
  }

  const int payload_size = static_cast<int>(payload.size());
  flow.write_buf = base::MakeRefCounted<StringIOBuffer>(std::move(payload));
  flow.write_pending = true;
  int rv = connection->WriteDatagramToServer(
      flow.write_buf.get(), payload_size,
      base::BindOnce(&NaiveUdpAssociation::OnFlowWriteComplete,
                     weak_ptr_factory_.GetWeakPtr(), flow.generation));
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&NaiveUdpAssociation::OnFlowWriteComplete,
                       weak_ptr_factory_.GetWeakPtr(), flow.generation, rv));
  }
}

void NaiveUdpAssociation::OnFlowWriteComplete(uint64_t generation, int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  auto it = FindFlow(generation);
  if (it == flows_.end()) {
    return;
  }
  const HostPortPair& target = it->first;
  TargetFlow& flow = it->second;
  DCHECK(flow.write_pending);
  DCHECK(flow.write_buf);
  flow.write_pending = false;
  flow.write_buf = nullptr;
  if (result == ERR_MSG_TOO_BIG) {
    DLOG(WARNING) << "Dropping oversized SOCKS5 UDP datagram for "
                  << target.ToString();
    DoNextFlowWrite(target, flow);
    return;
  }
  if (result < 0) {
    CloseFlow(target, result);
    return;
  }
  DoNextFlowWrite(target, flow);
}

void NaiveUdpAssociation::DoFlowRead(const HostPortPair& target,
                                     TargetFlow& flow) {
  if (flow.read_pending) {
    return;
  }

  NaiveConnection* connection =
      flow.connection_id.has_value()
          ? owner_->FindConnection(*flow.connection_id)
          : nullptr;
  if (!connection) {
    CloseFlow(target, ERR_SOCKET_NOT_CONNECTED);
    return;
  }

  if (!flow.read_buf) {
    flow.read_buf = base::MakeRefCounted<IOBufferWithSize>(kUdpBufferSize);
  }
  flow.read_pending = true;
  int rv = connection->ReadDatagramFromServer(
      flow.read_buf.get(), kUdpBufferSize,
      base::BindOnce(&NaiveUdpAssociation::OnFlowReadComplete,
                     weak_ptr_factory_.GetWeakPtr(), flow.generation));
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&NaiveUdpAssociation::OnFlowReadComplete,
                       weak_ptr_factory_.GetWeakPtr(), flow.generation, rv));
  }
}

void NaiveUdpAssociation::OnFlowReadComplete(uint64_t generation, int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  auto it = FindFlow(generation);
  if (it == flows_.end()) {
    return;
  }
  const HostPortPair& target = it->first;
  TargetFlow& flow = it->second;
  DCHECK(flow.read_pending);
  DCHECK(flow.read_buf);
  flow.read_pending = false;
  if (result == ERR_MSG_TOO_BIG) {
    flow.last_used = base::TimeTicks::Now();
    ResetIdleTimer();
    DLOG(WARNING) << "Dropping oversized CONNECT-UDP datagram for "
                  << target.ToString();
    DoFlowRead(target, flow);
    return;
  }
  if (result < 0) {
    // A CONNECT-UDP stream is a synthetic per-target flow. Peer EOF ends that
    // flow normally and must not be reported as a failed proxy connection.
    CloseFlow(target, result == ERR_CONNECTION_CLOSED ? OK : result);
    return;
  }
  const int payload_size = result;
  flow.last_used = base::TimeTicks::Now();
  ResetIdleTimer();

  std::string_view payload(flow.read_buf->data(), payload_size);
  std::optional<std::string> packet = BuildSocks5UdpPacket(target, payload);
  if (packet.has_value() && client_udp_endpoint_.has_value()) {
    QueueUdpSend(std::move(*packet), *client_udp_endpoint_);
  } else if (!packet.has_value()) {
    DLOG(WARNING) << "Failed to build SOCKS5 UDP response packet for "
                  << target.ToString() << " payload length " << payload_size;
  }
  it = FindFlow(generation);
  if (it != flows_.end()) {
    DoFlowRead(it->first, it->second);
  }
}

void NaiveUdpAssociation::QueueUdpSend(std::string packet,
                                       const IPEndPoint& endpoint) {
  if (!udp_send_pending_ && udp_send_queue_.empty()) {
    DoUdpSend(std::move(packet), endpoint);
    return;
  }
  if (limits_.max_queued_udp_send_bytes != 0 &&
      packet.size() > limits_.max_queued_udp_send_bytes) {
    DLOG(WARNING) << "Dropping SOCKS5 UDP response datagram: packet exceeds "
                     "send queue byte limit";
    return;
  }

  bool discarded = false;
  while (!udp_send_queue_.empty() &&
         ((limits_.max_queued_udp_sends != 0 &&
           udp_send_queue_.size() >= limits_.max_queued_udp_sends) ||
          (limits_.max_queued_udp_send_bytes != 0 &&
           udp_send_queue_bytes_ >
               limits_.max_queued_udp_send_bytes - packet.size()))) {
    DCHECK_GE(udp_send_queue_bytes_, udp_send_queue_.front().first.size());
    udp_send_queue_bytes_ -= udp_send_queue_.front().first.size();
    udp_send_queue_.pop_front();
    discarded = true;
  }
  if (discarded) {
    DLOG(WARNING) << "Discarding oldest SOCKS5 UDP response datagrams: send "
                     "queue is full";
  }
  udp_send_queue_bytes_ += packet.size();
  udp_send_queue_.emplace_back(std::move(packet), endpoint);
  if (!udp_send_pending_) {
    DoUdpSend();
  }
}

void NaiveUdpAssociation::DoUdpSend() {
  if (udp_send_queue_.empty()) {
    return;
  }

  auto [packet, endpoint] = std::move(udp_send_queue_.front());
  DCHECK_GE(udp_send_queue_bytes_, packet.size());
  udp_send_queue_bytes_ -= packet.size();
  udp_send_queue_.pop_front();
  DoUdpSend(std::move(packet), endpoint);
}

void NaiveUdpAssociation::DoUdpSend(std::string packet,
                                    const IPEndPoint& endpoint) {
  DCHECK(!udp_send_pending_);
  DCHECK(!udp_send_buf_);
  const int packet_size = static_cast<int>(packet.size());
  udp_send_address_ = endpoint;
  udp_send_buf_ = base::MakeRefCounted<StringIOBuffer>(std::move(packet));
  udp_send_pending_ = true;
  int rv = udp_socket_->SendTo(
      udp_send_buf_.get(), packet_size, udp_send_address_,
      base::BindOnce(&NaiveUdpAssociation::OnUdpSendComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveUdpAssociation::OnUdpSendComplete,
                                  weak_ptr_factory_.GetWeakPtr(), rv));
  }
}

void NaiveUdpAssociation::OnUdpSendComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(udp_send_pending_);
  DCHECK(udp_send_buf_);
  udp_send_pending_ = false;
  udp_send_buf_ = nullptr;
  if (result == ERR_MSG_TOO_BIG) {
    DLOG(WARNING) << "Dropping oversized SOCKS5 UDP response packet";
    DoUdpSend();
    return;
  }
  if (result < 0) {
    owner_->CloseUdpAssociation(this, result);
    return;
  }
  DoUdpSend();
}

void NaiveUdpAssociation::CloseFlow(const HostPortPair& target, int reason) {
  auto it = flows_.find(target);
  if (it == flows_.end()) {
    return;
  }
  RemoveFlow(it, reason);
}

void NaiveUdpAssociation::ResetIdleTimer() {
  idle_timer_.Start(FROM_HERE, association_idle_timeout_,
                    base::BindOnce(&NaiveUdpAssociation::OnIdleTimeout,
                                   weak_ptr_factory_.GetWeakPtr()));
}

void NaiveUdpAssociation::OnIdleTimeout() {
  owner_->CloseUdpAssociation(this, ERR_TIMED_OUT);
}

}  // namespace net
