// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_NAIVE_NAIVE_UDP_ASSOCIATION_H_
#define NET_TOOLS_NAIVE_NAIVE_UDP_ASSOCIATION_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/containers/circular_deque.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"

namespace net {

// A value of zero disables the corresponding limit. Limits apply per SOCKS5
// UDP association; the two flow queue limits apply separately to each target.
struct NaiveUdpAssociationLimits {
  size_t max_target_flows = 128;
  size_t max_queued_datagrams_per_flow = 16;
  size_t max_queued_bytes_per_flow = 256 * 1024;
  size_t max_queued_udp_sends = 64;
  size_t max_queued_udp_send_bytes = 1024 * 1024;
};

class IOBuffer;
class NaiveConnection;
class NaiveProxy;
class StreamSocket;
class UDPServerSocket;

// Owns one SOCKS5 UDP ASSOCIATE control connection and its per-target
// CONNECT-UDP flows.
class NaiveUdpAssociation {
 public:
  NaiveUdpAssociation(NaiveProxy* owner,
                      std::unique_ptr<StreamSocket> control_socket,
                      std::unique_ptr<UDPServerSocket> udp_socket,
                      const HostPortPair& requested_client_endpoint,
                      base::TimeDelta connect_udp_timeout,
                      base::TimeDelta tunnel_timeout,
                      base::TimeDelta association_idle_timeout,
                      const NaiveUdpAssociationLimits& limits);
  ~NaiveUdpAssociation();
  NaiveUdpAssociation(const NaiveUdpAssociation&) = delete;
  NaiveUdpAssociation& operator=(const NaiveUdpAssociation&) = delete;

  void Start();
  void CloseTargetFlows();

 private:
  struct TargetFlow {
    uint64_t generation = 0;
    std::optional<unsigned int> connection_id;
    bool connected = false;
    bool read_pending = false;
    bool write_pending = false;
    base::TimeTicks created_at = base::TimeTicks::Now();
    base::TimeTicks last_used = base::TimeTicks::Now();
    base::circular_deque<std::string> write_queue;
    size_t write_queue_bytes = 0;
    scoped_refptr<IOBuffer> read_buf;
    scoped_refptr<IOBuffer> write_buf;
  };
  using FlowMap = std::map<HostPortPair, TargetFlow>;

  void DoControlRead();
  void OnControlReadComplete(int result);
  void DoUdpRead();
  void OnUdpReadComplete(int result);
  bool OnUdpPacket(const HostPortPair& destination, std::string payload);
  void OnFlowCleanupTimer();
  FlowMap::iterator FindFlow(uint64_t generation);
  void RemoveFlow(FlowMap::iterator flow, int reason);
  void DoFlowConnect(const HostPortPair& target, TargetFlow& flow);
  void OnFlowConnectComplete(uint64_t generation, int result);
  bool QueueWrite(const HostPortPair& target,
                  TargetFlow& flow,
                  std::string payload);
  void DoFlowWrite(const HostPortPair& target,
                   TargetFlow& flow,
                   std::string payload);
  void DoNextFlowWrite(const HostPortPair& target, TargetFlow& flow);
  void OnFlowWriteComplete(uint64_t generation, int result);
  void DoFlowRead(const HostPortPair& target, TargetFlow& flow);
  void OnFlowReadComplete(uint64_t generation, int result);
  void QueueUdpSend(std::string packet, const IPEndPoint& endpoint);
  void DoUdpSend();
  void DoUdpSend(std::string packet, const IPEndPoint& endpoint);
  void OnUdpSendComplete(int result);
  void CloseFlow(const HostPortPair& target, int reason);
  void ResetIdleTimer();
  void OnIdleTimeout();

  NaiveProxy* owner_;
  std::unique_ptr<StreamSocket> control_socket_;
  std::unique_ptr<UDPServerSocket> udp_socket_;
  HostPortPair requested_client_endpoint_;
  base::TimeDelta connect_udp_timeout_;
  base::TimeDelta tunnel_timeout_;
  base::TimeDelta association_idle_timeout_;
  NaiveUdpAssociationLimits limits_;

  scoped_refptr<IOBuffer> control_read_buf_;
  scoped_refptr<IOBuffer> udp_read_buf_;
  IPEndPoint udp_read_address_;
  IPAddress client_ip_address_;
  std::optional<IPEndPoint> client_udp_endpoint_;

  bool udp_send_pending_ = false;
  scoped_refptr<IOBuffer> udp_send_buf_;
  IPEndPoint udp_send_address_;
  base::circular_deque<std::pair<std::string, IPEndPoint>> udp_send_queue_;
  size_t udp_send_queue_bytes_ = 0;

  FlowMap flows_;
  std::map<uint64_t, FlowMap::iterator> flow_by_generation_;
  uint64_t next_flow_generation_ = 1;
  base::OneShotTimer flow_cleanup_timer_;
  base::OneShotTimer idle_timer_;

  base::WeakPtrFactory<NaiveUdpAssociation> weak_ptr_factory_{this};
};

}  // namespace net

#endif  // NET_TOOLS_NAIVE_NAIVE_UDP_ASSOCIATION_H_
