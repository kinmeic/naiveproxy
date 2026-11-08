// Copyright 2018 The Chromium Authors. All rights reserved.
// Copyright 2018 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/naive/naive_proxy.h"

#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_network_session.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_list.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/socket/udp_server_socket.h"
#include "net/tools/naive/http_proxy_server_socket.h"
#include "net/tools/naive/naive_proxy_delegate.h"
#include "net/tools/naive/socks5_server_socket.h"

namespace net {
namespace {
constexpr base::TimeDelta kIdleCheckPeriod = base::Minutes(1);
}  // namespace

NaiveProxy::Tunnel::Tunnel() = default;
NaiveProxy::Tunnel::~Tunnel() = default;

NaiveProxy::NaiveProxy(std::unique_ptr<ServerSocket> listen_socket,
                       ClientProtocol protocol,
                       const std::string& listen_user,
                       const std::string& listen_pass,
                       int concurrency,
                       int tunnel_timeout,
                       int idle_timeout,
                       RedirectResolver* resolver,
                       HttpNetworkSession* session,
                       bool masque_udp,
                       const std::string& masque_udp_path_template,
                       int connect_udp_timeout,
                       int socks_udp_association_timeout,
                       const NaiveUdpAssociationLimits& udp_limits,
                       const NetworkTrafficAnnotationTag& traffic_annotation,
                       const std::vector<PaddingType>& supported_padding_types)
    : listen_socket_(std::move(listen_socket)),
      protocol_(protocol),
      listen_user_(listen_user),
      listen_pass_(listen_pass),
      concurrency_(concurrency),
      tunnel_timeout_(base::Seconds(tunnel_timeout)),
      idle_timeout_(base::Seconds(idle_timeout)),
      resolver_(resolver),
      session_(session),
      masque_udp_(masque_udp),
      masque_udp_path_template_(masque_udp_path_template),
      connect_udp_timeout_(base::Seconds(connect_udp_timeout)),
      socks_udp_association_timeout_(
          base::Seconds(socks_udp_association_timeout)),
      udp_limits_(udp_limits),
      net_log_(
          NetLogWithSource::Make(session->net_log(), NetLogSourceType::NONE)),
      next_id_(0),
      next_state_(State::kAccept),
      tunnels_(concurrency),
      traffic_annotation_(traffic_annotation),
      supported_padding_types_(supported_padding_types) {
  const auto& proxy_config = static_cast<ConfiguredProxyResolutionService*>(
                                 session_->proxy_resolution_service())
                                 ->config();
  DCHECK(proxy_config);
  const ProxyList& proxy_list =
      proxy_config.value().value().proxy_rules().single_proxies;
  DCHECK(!proxy_list.IsEmpty());
  proxy_info_.UseProxyList(proxy_list);
  proxy_info_.set_traffic_annotation(
      net::MutableNetworkTrafficAnnotationTag(traffic_annotation_));
  if (!proxy_info_.is_direct()) {
    const ProxyChain& proxy_chain = proxy_info_.proxy_chain();
    std::tie(last_proxy_partial_chain_, last_proxy_server_) =
        proxy_chain.SplitLast();
  }

  DCHECK(listen_socket_);
  // Start accepting connections in next run loop in case when delegate is not
  // ready to get callbacks.
  io_callback_ = base::BindRepeating(&NaiveProxy::OnIOComplete,
                                     weak_ptr_factory_.GetWeakPtr());
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&NaiveProxy::OnIOComplete,
                                weak_ptr_factory_.GetWeakPtr(), OK));

  cleanup_timer_.Start(FROM_HERE, kIdleCheckPeriod, this,
                       &NaiveProxy::CleanUpIdleConnections);
}

NaiveProxy::~NaiveProxy() = default;

void NaiveProxy::OnIOComplete(int result) {
  DCHECK_NE(next_state_, State::kNone);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveProxy::OnIOComplete,
                                  weak_ptr_factory_.GetWeakPtr(), OK));
  }
}

int NaiveProxy::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, State::kNone);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = State::kNone;
    switch (state) {
      case State::kAccept:
        DCHECK_EQ(OK, rv);
        rv = DoAccept();
        break;
      case State::kAcceptComplete:
        rv = DoAcceptComplete(rv);
        break;
      case State::kPreamble:
        DCHECK_EQ(OK, rv);
        rv = DoPreamble();
        break;
      case State::kPreambleComplete:
        rv = DoPreambleComplete(rv);
        break;
      case State::kConnect:
        DCHECK_EQ(OK, rv);
        rv = DoConnect();
        break;
      default:
        rv = ERR_UNEXPECTED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != State::kNone);
  return rv;
}

int NaiveProxy::DoAccept() {
  next_state_ = State::kAcceptComplete;
  return listen_socket_->Accept(&accepted_socket_, io_callback_);
}

int NaiveProxy::DoAcceptComplete(int result) {
  if (result != OK) {
    next_state_ = State::kAccept;
    LOG(ERROR) << "Accept error: " << ErrorToShortString(result);
    if (result == ERR_INSUFFICIENT_RESOURCES) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&NaiveProxy::OnIOComplete,
                         weak_ptr_factory_.GetWeakPtr(), OK),
          base::Seconds(1));
      return ERR_IO_PENDING;
    }
    return OK;
  }

  // Keep the selection stable across an asynchronous preamble. Existing
  // CONNECT-UDP flows may advance next_id_ while the preamble is in flight.
  accepted_tunnel_ = &tunnels_[next_id_ % concurrency_];
  Tunnel& tunnel = *accepted_tunnel_;
  base::TimeTicks now = base::TimeTicks::Now();
  if (IsSessionCapable()) {
    if (tunnel.deadline.is_null()) {
      tunnel.nak_created_at = now;
      tunnel.deadline = now + tunnel_timeout_;
      next_state_ = State::kPreamble;
    } else if (now > tunnel.deadline) {
      tunnel.nak = NetworkAnonymizationKey::CreateTransient();
      tunnel.nak_created_at = now;
      tunnel.deadline = now + tunnel_timeout_;
      tunnel.url_getter.reset();
      next_state_ = State::kPreamble;
    } else {
      DCHECK(tunnel.url_getter != nullptr);
      tunnel.url_getter->StartOne();
      next_state_ = State::kConnect;
    }
  } else {
    next_state_ = State::kConnect;
  }
  return OK;
}

// Possible exit states: State::kAccept, State::kPreambleComplete
int NaiveProxy::DoPreamble() {
  DCHECK(accepted_tunnel_);
  Tunnel& tunnel = *accepted_tunnel_;
  DCHECK(WillCreateSession(tunnel.nak));
  tunnel.url_getter = std::make_unique<PreambleGetter>(proxy_info_, session_,
                                                       tunnel.nak, net_log_);
  next_state_ = State::kPreambleComplete;
  return tunnel.url_getter->Start(io_callback_);
}

int NaiveProxy::DoPreambleComplete(int result) {
  if (result != OK) {
    LOG(WARNING) << "Preamble error: " << ErrorToShortString(result);
    // Preamble error doesn't prevent Connect().
  }
  next_state_ = State::kConnect;
  return OK;
}

int NaiveProxy::DoConnect() {
  auto negotiated_client_padding =
      std::make_unique<PaddingType>(PaddingType::kNone);

  // Once accepted_socket_ is moved, the next Accept can start.
  next_state_ = State::kAccept;

  DCHECK(accepted_tunnel_);
  const Tunnel& tunnel = *accepted_tunnel_;
  std::unique_ptr<StreamSocket> socket;
  if (protocol_ == ClientProtocol::kSocks5) {
    base::OnceCallback<int(Socks5ServerSocket*, IPEndPoint*)>
        udp_associate_callback;
    if (masque_udp_ && proxy_info_.proxy_chain().length() == 1 &&
        last_proxy_server_.is_quic()) {
      // The proxy owns the connection that owns this callback.
      udp_associate_callback = base::BindOnce(
          &NaiveProxy::PrepareSocks5UdpAssociate, base::Unretained(this));
    }
    auto socks_socket = std::make_unique<Socks5ServerSocket>(
        std::move(accepted_socket_), listen_user_, listen_pass_,
        traffic_annotation_, std::move(udp_associate_callback));
    socket = std::move(socks_socket);
  } else if (protocol_ == ClientProtocol::kHttp) {
    socket = std::make_unique<HttpProxyServerSocket>(
        std::move(accepted_socket_), listen_user_, listen_pass_,
        negotiated_client_padding.get(), traffic_annotation_,
        supported_padding_types_);
  } else if (protocol_ == ClientProtocol::kRedir) {
    socket = std::move(accepted_socket_);
  } else {
    return OK;
  }

  auto connection_ptr = std::make_unique<NaiveConnection>(
      protocol_, std::move(negotiated_client_padding), proxy_info_, resolver_,
      session_, tunnel.nak, net_log_, std::move(socket), traffic_annotation_);
  accepted_tunnel_ = nullptr;
  auto* connection = connection_ptr.get();
  // The local handshake determines whether this is an outbound CONNECT or a
  // SOCKS5 UDP control association. Keep pointer identity only until then so
  // the control association never consumes an outbound connection ID.
  pending_connections_[connection] = std::move(connection_ptr);

  int result = connection->ConnectClient(
      base::BindOnce(&NaiveProxy::OnClientConnectComplete,
                     weak_ptr_factory_.GetWeakPtr(), connection));
  if (result == ERR_IO_PENDING) {
    // Connect result doesn't prevent the next Accept
    return OK;
  }
  OnClientConnectComplete(connection, result);
  return OK;
}

int NaiveProxy::PrepareSocks5UdpAssociate(Socks5ServerSocket* socks_socket,
                                          IPEndPoint* response_endpoint) {
  if (udp_associations_.size() + pending_udp_associations_.size() >= 256) {
    return ERR_INSUFFICIENT_RESOURCES;
  }
  auto udp_socket =
      std::make_unique<UDPServerSocket>(session_->net_log(), NetLogSource());
  IPEndPoint tcp_local_address;
  int rv = socks_socket->GetLocalAddress(&tcp_local_address);
  if (rv == OK && (!tcp_local_address.address().IsValid() ||
                   tcp_local_address.address().IsZero())) {
    DLOG(WARNING) << "Cannot bind SOCKS5 UDP relay to unspecified TCP local "
                     "address "
                  << tcp_local_address.ToString();
    rv = ERR_ADDRESS_INVALID;
  }
  if (rv == OK) {
    rv = udp_socket->Listen(IPEndPoint(tcp_local_address.address(), 0));
  }
  IPEndPoint udp_local_address;
  if (rv == OK) {
    rv = udp_socket->GetLocalAddress(&udp_local_address);
  }
  if (rv != OK) {
    LOG(ERROR) << "Failed to bind SOCKS5 UDP relay: " << ErrorToShortString(rv);
    return rv;
  }

  *response_endpoint = udp_local_address;
  pending_udp_associations_[socks_socket] = {.socket = std::move(udp_socket)};
  return OK;
}

void NaiveProxy::OnClientConnectComplete(NaiveConnection* connection,
                                         int result) {
  auto connection_it = pending_connections_.find(connection);
  if (connection_it == pending_connections_.end()) {
    return;
  }
  auto* socks_socket =
      protocol_ == ClientProtocol::kSocks5
          ? static_cast<Socks5ServerSocket*>(connection->client_socket())
          : nullptr;
  if (result != OK) {
    if (socks_socket) {
      pending_udp_associations_.erase(socks_socket);
    }
    DLOG(INFO) << "Client handshake closed: " << ErrorToShortString(result);
    base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
        FROM_HERE, std::move(connection_it->second));
    pending_connections_.erase(connection_it);
    return;
  }

  if (connection->is_socks_udp_associate()) {
    DCHECK(socks_socket);
    auto pending_it = pending_udp_associations_.find(socks_socket);
    DCHECK(pending_it != pending_udp_associations_.end());
    if (pending_it == pending_udp_associations_.end()) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
          FROM_HERE, std::move(connection_it->second));
      pending_connections_.erase(connection_it);
      return;
    }

    std::unique_ptr<StreamSocket> control_socket =
        connection->ReleaseClientSocket();
    const HostPortPair requested_client_endpoint =
        static_cast<Socks5ServerSocket*>(control_socket.get())
            ->request_endpoint();
    base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
        FROM_HERE, std::move(connection_it->second));
    pending_connections_.erase(connection_it);

    PendingUdpAssociation pending = std::move(pending_it->second);
    pending_udp_associations_.erase(pending_it);

    auto association = std::make_unique<NaiveUdpAssociation>(
        this, std::move(control_socket), std::move(pending.socket),
        requested_client_endpoint, connect_udp_timeout_, tunnel_timeout_,
        socks_udp_association_timeout_, udp_limits_);
    NaiveUdpAssociation* association_ptr = association.get();
    udp_associations_[association_ptr] = std::move(association);
    association_ptr->Start();
    return;
  }

  if (socks_socket) {
    pending_udp_associations_.erase(socks_socket);
  }

  connection->set_id(next_id_++);
  const unsigned int connection_id = connection->id();
  connection_by_id_[connection_id] = std::move(connection_it->second);
  pending_connections_.erase(connection_it);
  result = connection->ConnectServer(
      base::BindOnce(&NaiveProxy::OnConnectComplete,
                     weak_ptr_factory_.GetWeakPtr(), connection_id));
  if (result != ERR_IO_PENDING) {
    HandleConnectResult(connection, result);
  }
}

void NaiveProxy::OnConnectComplete(unsigned int connection_id, int result) {
  auto* connection = FindConnection(connection_id);
  if (!connection) {
    return;
  }
  HandleConnectResult(connection, result);
}

void NaiveProxy::HandleConnectResult(NaiveConnection* connection, int result) {
  if (result != OK) {
    Close(connection->id(), result);
    return;
  }
  DoRun(connection);
}

void NaiveProxy::DoRun(NaiveConnection* connection) {
  int result = connection->Run(base::BindOnce(&NaiveProxy::OnRunComplete,
                                              weak_ptr_factory_.GetWeakPtr(),
                                              connection->id()));
  if (result == ERR_IO_PENDING) {
    return;
  }
  HandleRunResult(connection, result);
}

void NaiveProxy::OnRunComplete(unsigned int connection_id, int result) {
  auto* connection = FindConnection(connection_id);
  if (!connection) {
    return;
  }
  HandleRunResult(connection, result);
}

void NaiveProxy::HandleRunResult(NaiveConnection* connection, int result) {
  Close(connection->id(), result);
}

void NaiveProxy::Close(unsigned int connection_id, int reason) {
  auto it = connection_by_id_.find(connection_id);
  if (it == connection_by_id_.end()) {
    return;
  }

  LOG(INFO) << (it->second->is_datagram() ? "CONNECT-UDP " : "Connection ")
            << connection_id << " closed: " << ErrorToShortString(reason);

  // The call stack might have callbacks which still have the pointer of
  // connection. Instead of referencing connection with ID all the time,
  // destroys the connection in next run loop to make sure any pending
  // callbacks in the call stack return.
  base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(it->second));
  connection_by_id_.erase(it);
}

void NaiveProxy::CloseUdpAssociation(NaiveUdpAssociation* association,
                                     int reason) {
  auto it = udp_associations_.find(association);
  if (it == udp_associations_.end()) {
    return;
  }

  DLOG(INFO) << "SOCKS5 UDP association closed: " << ErrorToShortString(reason);

  it->second->CloseTargetFlows();
  base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(it->second));
  udp_associations_.erase(it);

  if (udp_associations_.empty()) {
    // Run after the DeleteSoon tasks posted by CloseTargetFlows(), so their
    // HTTP streams no longer keep an otherwise idle proxy session alive.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveProxy::CleanUpIdleConnections,
                                  weak_ptr_factory_.GetWeakPtr()));
  }
}

NaiveConnection* NaiveProxy::FindConnection(unsigned int connection_id) {
  auto it = connection_by_id_.find(connection_id);
  if (it == connection_by_id_.end()) {
    return nullptr;
  }
  return it->second.get();
}

NaiveConnection* NaiveProxy::CreateDatagramConnection(
    const HostPortPair& target) {
  // Bound aggregate UDP admission across associations, including connecting
  // flows. Existing TCP connections also consume this admission budget.
  if (connection_by_id_.size() >= 1024) {
    return nullptr;
  }
  const unsigned int connection_id = next_id_++;
  Tunnel& tunnel = tunnels_[connection_id % concurrency_];
  const base::TimeTicks now = base::TimeTicks::Now();
  if (now - tunnel.nak_created_at >= tunnel_timeout_) {
    tunnel.nak = NetworkAnonymizationKey::CreateTransient();
    tunnel.nak_created_at = now;
    tunnel.deadline = base::TimeTicks();
    tunnel.url_getter.reset();
  }

  auto negotiated_client_padding =
      std::make_unique<PaddingType>(PaddingType::kNone);
  auto connection = std::make_unique<NaiveConnection>(
      ClientProtocol::kSocks5, std::move(negotiated_client_padding),
      proxy_info_, resolver_, session_, tunnel.nak, net_log_, nullptr,
      traffic_annotation_, target, masque_udp_path_template_);
  connection->set_id(connection_id);

  NaiveConnection* connection_ptr = connection.get();
  connection_by_id_[connection_ptr->id()] = std::move(connection);
  return connection_ptr;
}

NaiveProxyDelegate* NaiveProxy::naive_proxy_delegate() const {
  auto* proxy_delegate =
      static_cast<NaiveProxyDelegate*>(session_->context().proxy_delegate);
  DCHECK(proxy_delegate);
  return proxy_delegate;
}

bool NaiveProxy::IsSessionCapable() const {
  if (proxy_info_.is_direct()) {
    return false;
  }
  // TODO(klzgrad): HTTP/1 https proxy will fail
  return last_proxy_server_.is_secure_http_like();
}

bool NaiveProxy::WillCreateSession(const NetworkAnonymizationKey& nak) const {
  if (last_proxy_server_.is_https()) {
    SpdySessionKey key(last_proxy_server_.host_port_pair(),
                       PRIVACY_MODE_DISABLED, last_proxy_partial_chain_,
                       SessionUsage::kProxy, SocketTag(), nak,
                       SecureDnsPolicy::kDisable,
                       /*disable_cert_verification_network_fetches=*/true,
                       handles::kInvalidNetworkHandle);
    return !session_->spdy_session_pool()->FindAvailableSession(
        key, /*enable_ip_based_pooling_for_h2=*/false,
        /*is_websocket=*/false, net_log_);
  }
  if (last_proxy_server_.is_quic()) {
    QuicSessionKey key(
        last_proxy_server_.host_port_pair(), PRIVACY_MODE_DISABLED,
        last_proxy_partial_chain_, SessionUsage::kProxy, SocketTag(), nak,
        SecureDnsPolicy::kDisable, /*require_dns_https_alpn=*/false,
        /*disable_cert_verification_network_fetches=*/true,
        handles::kInvalidNetworkHandle);
    url::SchemeHostPort destination("https", last_proxy_server_.GetHost(),
                                    last_proxy_server_.GetPort(),
                                    url::SchemeHostPort::ALREADY_CANONICALIZED);
    return !session_->quic_session_pool()->CanUseExistingSession(key,
                                                                 destination);
  }
  return false;
}

void NaiveProxy::CleanUpIdleConnections() {
  const base::TimeTicks now = base::TimeTicks::Now();
  std::vector<NaiveConnection*> idle_conns;
  for (const auto& [id, conn] : connection_by_id_) {
    // CONNECT-UDP lifetime is managed by its SOCKS5 UDP association. Closing
    // one here would bypass the flow state that owns its pending callbacks.
    if (conn->is_datagram()) {
      continue;
    }
    base::TimeDelta idle = now - conn->GetLastWriteTime();
    base::TimeDelta idle_timeout = idle_timeout_;
    const Tunnel& tunnel = tunnels_[id % concurrency_];
    if (!tunnel.deadline.is_null() &&
        (conn->network_anonymization_key() != tunnel.nak ||
         now > tunnel.deadline)) {
      idle_timeout = idle_timeout_ / 10;
    }
    if (idle > idle_timeout) {
      idle_conns.push_back(conn.get());
    }
  }
  for (NaiveConnection* conn : idle_conns) {
    unsigned int id = conn->id();
    conn->Disconnect();
    // A connection still in Connect() has no run callback to remove it.
    Close(id, ERR_TIMED_OUT);
  }
  session_->CloseIdleConnections("Rotate old tunnels");
}

}  // namespace net
