// Copyright 2024 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/naive_config.h"

#include <algorithm>
#include <iostream>
#include <utility>

#include "base/files/file_util.h"
#include "base/strings/escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/url_util.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/http/connect_udp_helper.h"
#include "url/gurl.h"

namespace net {
namespace {
ProxyServer MyProxyUriToProxyServer(std::string_view uri) {
  if (uri.compare(0, 7, "quic://") == 0) {
    return ProxySchemeHostAndPortToProxyServer(ProxyServer::SCHEME_QUIC,
                                               uri.substr(7));
  }
  return ProxyUriToProxyServer(uri, ProxyServer::SCHEME_INVALID);
}

bool ParseSizeLimit(const base::DictValue& value,
                    std::string_view name,
                    size_t* output) {
  const base::Value* v = value.Find(name);
  if (!v) {
    return true;
  }
  if (std::optional<int> i = v->GetIfInt()) {
    if (*i >= 0) {
      *output = static_cast<size_t>(*i);
      return true;
    }
  } else if (const std::string* str = v->GetIfString()) {
    if (base::StringToSizeT(*str, output)) {
      return true;
    }
  }
  std::cerr << "Invalid " << name << std::endl;
  return false;
}
}  // namespace

NaiveListenConfig::NaiveListenConfig() = default;
NaiveListenConfig::NaiveListenConfig(const NaiveListenConfig&) = default;
NaiveListenConfig::~NaiveListenConfig() = default;

bool NaiveListenConfig::Parse(const std::string& str) {
  GURL url(str);
  if (url.scheme() == "socks") {
    protocol = ClientProtocol::kSocks5;
  } else if (url.scheme() == "http") {
    protocol = ClientProtocol::kHttp;
  } else if (url.scheme() == "redir") {
#if BUILDFLAG(IS_LINUX)
    protocol = ClientProtocol::kRedir;
#else
    std::cerr << "Redir protocol only supports Linux." << std::endl;
    return false;
#endif
  } else {
    std::cerr << "Invalid scheme in " << str << std::endl;
    return false;
  }

  if (!url.username().empty()) {
    user = base::UnescapeBinaryURLComponent(url.username());
  }
  if (!url.password().empty()) {
    pass = base::UnescapeBinaryURLComponent(url.password());
  }

  if (!url.host().empty()) {
    addr = url.HostNoBrackets();
  }

  int effective_port = url.EffectiveIntPort();
  if (effective_port == url::PORT_INVALID) {
    std::cerr << "Invalid port in " << str << std::endl;
    return false;
  }
  if (effective_port != url::PORT_UNSPECIFIED) {
    port = effective_port;
  }

  return true;
}

NaiveConfig::NaiveConfig() = default;
NaiveConfig::NaiveConfig(const NaiveConfig&) = default;
NaiveConfig::~NaiveConfig() = default;

bool NaiveConfig::Parse(const base::DictValue& value) {
  if (const base::Value* v = value.Find("listen")) {
    std::vector<std::string> listen_strs;
    if (const std::string* str = v->GetIfString()) {
      listen_strs.push_back(*str);
    } else if (const base::ListValue* strs = v->GetIfList()) {
      for (const auto& str_e : *strs) {
        if (const std::string* s = str_e.GetIfString()) {
          listen_strs.push_back(*s);
        } else {
          std::cerr << "Invalid listen element" << std::endl;
          return false;
        }
      }
    } else {
      std::cerr << "Invalid listen" << std::endl;
      return false;
    }
    if (!listen_strs.empty()) {
      listen.clear();
    }
    for (const std::string& str : listen_strs) {
      if (!listen.emplace_back().Parse(str)) {
        return false;
      }
    }
  }

  if (const base::Value* v = value.Find("insecure-concurrency")) {
    if (std::optional<int> i = v->GetIfInt()) {
      insecure_concurrency = *i;
    } else if (const std::string* str = v->GetIfString()) {
      if (!base::StringToInt(*str, &insecure_concurrency)) {
        std::cerr << "Invalid concurrency" << std::endl;
        return false;
      }
    } else {
      std::cerr << "Invalid concurrency" << std::endl;
      return false;
    }
    if (insecure_concurrency < 1) {
      std::cerr << "Invalid concurrency" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("tunnel-timeout")) {
    if (std::optional<int> i = v->GetIfInt()) {
      tunnel_timeout = *i;
    } else if (const std::string* str = v->GetIfString()) {
      if (!base::StringToInt(*str, &tunnel_timeout)) {
        std::cerr << "Invalid tunnel-timeout" << std::endl;
        return false;
      }
    } else {
      std::cerr << "Invalid tunnel-timeout" << std::endl;
      return false;
    }
    if (tunnel_timeout < 1) {
      std::cerr << "Invalid tunnel-timeout" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("idle-timeout")) {
    if (std::optional<int> i = v->GetIfInt()) {
      idle_timeout = *i;
    } else if (const std::string* str = v->GetIfString()) {
      if (!base::StringToInt(*str, &idle_timeout)) {
        std::cerr << "Invalid idle-timeout" << std::endl;
        return false;
      }
    } else {
      std::cerr << "Invalid idle-timeout" << std::endl;
      return false;
    }
    if (idle_timeout < 1) {
      std::cerr << "Invalid idle-timeout" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("trusted-cert")) {
    const std::string* path = v->GetIfString();
    std::string contents;
    if (!path || path->empty() ||
        !base::ReadFileToStringWithMaxSize(
            base::FilePath::FromUTF8Unsafe(*path), &contents, 1024 * 1024)) {
      std::cerr << "Cannot read trusted-cert CA bundle" << std::endl;
      return false;
    }
    auto certs = X509Certificate::CreateCertificateListFromBytes(
        base::as_byte_span(contents), X509Certificate::FORMAT_AUTO);
    if (certs.empty()) {
      std::cerr << "Empty trusted-cert CA bundle" << std::endl;
      return false;
    }
    for (const auto& cert : certs) {
      auto parsed = x509_util::CreateParsedCertificate(
          bssl::UpRef(cert->cert_buffer()), nullptr);
      if (!parsed) {
        std::cerr << "Invalid trusted-cert certificate" << std::endl;
        return false;
      }
      trusted_certificates.push_back(std::move(parsed));
    }
  }

  if (const base::Value* v = value.Find("extra-headers")) {
    if (const std::string* str = v->GetIfString()) {
      extra_headers.AddHeadersFromString(*str);
    } else {
      std::cerr << "Invalid extra-headers" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("masque-udp")) {
    if (std::optional<bool> b = v->GetIfBool()) {
      masque_udp = *b;
    } else if (const std::string* str = v->GetIfString()) {
      if (*str == "true" || *str == "1") {
        masque_udp = true;
      } else if (*str == "false" || *str == "0") {
        masque_udp = false;
      } else {
        std::cerr << "Invalid masque-udp" << std::endl;
        return false;
      }
    } else {
      std::cerr << "Invalid masque-udp" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("masque-udp-path-template")) {
    if (const std::string* str = v->GetIfString(); str && !str->empty()) {
      if (!IsValidConnectUdpPathTemplate(*str)) {
        std::cerr << "Invalid masque-udp-path-template" << std::endl;
        return false;
      }
      masque_udp_path_template = *str;
    } else {
      std::cerr << "Invalid masque-udp-path-template" << std::endl;
      return false;
    }
  }

  for (auto [name, timeout] : {
           std::pair{"connect-udp-timeout", &connect_udp_timeout},
           std::pair{"socks-udp-association-timeout",
                     &socks_udp_association_timeout},
       }) {
    if (const base::Value* v = value.Find(name)) {
      if (std::optional<int> i = v->GetIfInt()) {
        *timeout = *i;
      } else if (const std::string* str = v->GetIfString()) {
        if (!base::StringToInt(*str, timeout)) {
          std::cerr << "Invalid " << name << std::endl;
          return false;
        }
      } else {
        std::cerr << "Invalid " << name << std::endl;
        return false;
      }
      if (*timeout < 1) {
        std::cerr << "Invalid " << name << std::endl;
        return false;
      }
    }
  }

  for (auto [name, limit] : {
           std::pair{"udp-max-target-flows", &udp_limits.max_target_flows},
           std::pair{"udp-max-queued-datagrams-per-flow",
                     &udp_limits.max_queued_datagrams_per_flow},
           std::pair{"udp-max-queued-bytes-per-flow",
                     &udp_limits.max_queued_bytes_per_flow},
           std::pair{"udp-max-queued-sends", &udp_limits.max_queued_udp_sends},
           std::pair{"udp-max-queued-send-bytes",
                     &udp_limits.max_queued_udp_send_bytes},
       }) {
    if (!ParseSizeLimit(value, name, limit)) {
      return false;
    }
  }

  if (const base::Value* v = value.Find("proxy")) {
    std::vector<std::string> proxy_strs;
    if (const std::string* str = v->GetIfString(); str && !str->empty()) {
      proxy_strs.push_back(*str);
    } else if (const base::ListValue* strs = v->GetIfList()) {
      for (const auto& str_e : *strs) {
        if (const std::string* s = str_e.GetIfString(); s && !s->empty()) {
          proxy_strs.push_back(*s);
        } else {
          std::cerr << "Invalid proxy element" << std::endl;
          return false;
        }
      }
    } else {
      std::cerr << "Invalid proxy argument" << std::endl;
      return false;
    }
    for (const std::string& str : proxy_strs) {
      PerProxyConfig proxy_config;
      base::StringTokenizer proxy_uri_list(str, ",");
      std::vector<ProxyServer> proxy_servers;
      bool seen_tcp = false;
      while (proxy_uri_list.GetNext()) {
        std::string token(proxy_uri_list.token());
        GURL url(token);

        std::u16string proxy_user;
        std::u16string proxy_pass;
        net::GetIdentityFromURL(url, &proxy_user, &proxy_pass);
        GURL::Replacements remove_auth;
        remove_auth.ClearUsername();
        remove_auth.ClearPassword();
        GURL url_no_auth = url.ReplaceComponents(remove_auth);
        std::string proxy_uri = url_no_auth.GetWithEmptyPath().spec();
        if (!proxy_uri.empty() && proxy_uri.back() == '/') {
          proxy_uri.pop_back();
        }

        proxy_servers.emplace_back(MyProxyUriToProxyServer(proxy_uri));
        const ProxyServer& last = proxy_servers.back();
        if (last.is_quic()) {
          if (seen_tcp) {
            std::cerr << "QUIC proxy cannot follow TCP-based proxies"
                      << std::endl;
            return false;
          }
          proxy_config.origins_to_force_quic_on.insert(
              url::SchemeHostPort(url));
        } else if (last.is_https() || last.is_http() || last.is_socks()) {
          seen_tcp = true;
        } else {
          std::cerr << "Invalid proxy scheme" << std::endl;
          return false;
        }

        AuthCredentials auth(proxy_user, proxy_pass);
        if (!auth.Empty()) {
          if (last.is_socks()) {
            std::cerr << "SOCKS proxy with auth is not supported" << std::endl;
          } else {
            std::string proxy_url(token);
            if (proxy_url.compare(0, 7, "quic://") == 0) {
              proxy_url.replace(0, 4, "https");
            }
            proxy_config.auth_store[url::SchemeHostPort{GURL{proxy_url}}] =
                auth;
          }
        }
      }

      if (proxy_servers.size() > 1 &&
          std::any_of(proxy_servers.begin(), proxy_servers.end(),
                      [](const ProxyServer& s) { return s.is_socks(); })) {
        // See net/socket/connect_job_params_factory.cc
        // DCHECK(proxy_server.is_socks());
        // DCHECK_EQ(1u, proxy_chain.length());
        std::cerr
            << "Multi-proxy chain containing SOCKS proxies is not supported."
            << std::endl;
        return false;
      }
      ProxyChain proxy_chain;
      if (std::any_of(proxy_servers.begin(), proxy_servers.end(),
                      [](const ProxyServer& s) { return s.is_quic(); })) {
        proxy_chain = ProxyChain::ForIpProtection(proxy_servers);
      } else {
        proxy_chain = ProxyChain(proxy_servers);
      }

      if (!proxy_chain.IsValid()) {
        std::cerr << "Invalid proxy chain" << std::endl;
        return false;
      }
      proxy_chains.push_back(proxy_chain);
      proxy_configs.push_back(std::move(proxy_config));
    }
  }

  if (const base::Value* v = value.Find("host-resolver-rules")) {
    if (const std::string* str = v->GetIfString()) {
      host_resolver_rules = *str;
    } else {
      std::cerr << "Invalid host-resolver-rules" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("resolver-range")) {
    if (const std::string* str = v->GetIfString(); str && !str->empty()) {
      if (!net::ParseCIDRBlock(*str, &resolver_range, &resolver_prefix)) {
        std::cerr << "Invalid resolver-range" << std::endl;
        return false;
      }
      if (resolver_range.IsIPv6()) {
        std::cerr << "IPv6 resolver range not supported" << std::endl;
        return false;
      }
    } else {
      std::cerr << "Invalid resolver-range" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("log")) {
    if (const std::string* str = v->GetIfString()) {
      if (!str->empty()) {
        log.logging_dest = logging::LOG_TO_FILE;
        log_file = base::FilePath::FromUTF8Unsafe(*str);
        log.log_file_path = log_file.value().c_str();
      } else {
        log.logging_dest = logging::LOG_TO_STDERR;
      }
    } else {
      std::cerr << "Invalid log" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("log-net-log")) {
    if (const std::string* str = v->GetIfString(); str && !str->empty()) {
      log_net_log = base::FilePath::FromUTF8Unsafe(*str);
    } else {
      std::cerr << "Invalid log-net-log" << std::endl;
      return false;
    }
  }

  if (const base::Value* v = value.Find("ssl-key-log-file")) {
    if (const std::string* str = v->GetIfString(); str && !str->empty()) {
      ssl_key_log_file = base::FilePath::FromUTF8Unsafe(*str);
    } else {
      std::cerr << "Invalid ssl-key-log-file" << std::endl;
      return false;
    }
  }

  if (value.contains("no-post-quantum")) {
    no_post_quantum = true;
  }

  return true;
}

}  // namespace net
