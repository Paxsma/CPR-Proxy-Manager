#pragma once
#ifndef cpr_proxy_manage
#define cpr_proxy_manage

#include <cstdint>
#include <memory>
#include <string>

#include <cpr/cpr.h>

namespace cpr_proxy_manager {

      /* Proxy protocols */
      enum class protocols : std::uint8_t {
            none,
            http,
            https,
            socks4,
            socks5,
            ftp,
            smtp,
            pop3,
            imap,
            dns,
            ftp_gateway,
            telnet,
            sip,
            websockets,
            rtsp,
            pptp,
            l2tp,
            mpls,
            ipsec,
            reverse_proxy,
            transparent_proxy,
            anonymizing_proxy,
            forward_proxy
      };

      /* Returns protocol string. */
      const char *const protocol_str(const protocols p) {

            switch (p) {
                  case protocols::none: {
                        return "none";
                  }
                  case protocols::http: {
                        return "http";
                  }
                  case protocols::https: {
                        return "https";
                  }
                  case protocols::socks4: {
                        return "socks4";
                  }
                  case protocols::socks5: {
                        return "socks5";
                  }
                  case protocols::ftp: {
                        return "ftp";
                  }
                  case protocols::smtp: {
                        return "smtp";
                  }
                  case protocols::pop3: {
                        return "pop3";
                  }
                  case protocols::imap: {
                        return "imap";
                  }
                  case protocols::dns: {
                        return "dns";
                  }
                  case protocols::ftp_gateway: {
                        return "ftp_gateway";
                  }
                  case protocols::telnet: {
                        return "telnet";
                  }
                  case protocols::sip: {
                        return "sip";
                  }
                  case protocols::websockets: {
                        return "websockets";
                  }
                  case protocols::rtsp: {
                        return "rtsp";
                  }
                  case protocols::pptp: {
                        return "pptp";
                  }
                  case protocols::l2tp: {
                        return "l2tp";
                  }
                  case protocols::mpls: {
                        return "mpls";
                  }
                  case protocols::ipsec: {
                        return "ipsec";
                  }
                  case protocols::reverse_proxy: {
                        return "reverse_proxy";
                  }
                  case protocols::transparent_proxy: {
                        return "transparent_proxy";
                  }
                  case protocols::anonymizing_proxy: {
                        return "anonymizing_proxy";
                  }
                  case protocols::forward_proxy: {
                        return "forward_proxy";
                  }
                  default: {
                        return "";
                  }
            }
      }

      struct proxy {

            protocols protocol = protocols::none;

            std::string url = "";
            std::string ip = "";
            std::string port = "";
            double ping = 0.0;

            /* user credentials */
            struct creds {
                  bool user_creds = false; /* Has user creds */
                  std::string username = "";
                  std::string password = "";
            } creds;

#pragma region cpr

            /* Link proxy to cpr session. */
            void cpr(cpr::Session &s) {
                  s.SetProxies(cpr::Proxies{{this->get_protocol_str(), this->url}});
                  if (this->creds.user_creds) {
                        s.SetAuth(cpr::Authentication(this->creds.username, this->creds.password, cpr::AuthMode::BASIC));
                  }
                  return;
            }

            /* Use get request on a URL and return status code. */
            std::size_t cpr_test(const std::string &url, const std::size_t mili = 700u /* Time out in miliseconds. */) {
                  cpr::Session session;
                  this->cpr(session);
                  session.SetUrl(cpr::Url(this->url));
                  session.SetTimeout(cpr::Timeout(static_cast<std::int32_t>(mili)));
                  return session.Get().status_code;
            }

#pragma endregion

#pragma region load

            void load(const std::string &ip, const std::string &port, const protocols protocol) {
                  this->ip = ip;
                  this->port = port;
                  this->protocol = protocol;
                  this->set_url();
                  return;
            }

            void load(const std::string &ip, const std::string &port, const protocols protocol, const std::string &username, const std::string &password) {
                  this->ip = ip;
                  this->port = port;
                  this->protocol = protocol;
                  this->ping = ping;
                  this->creds.user_creds = true;
                  this->creds.username = username;
                  this->creds.password = password;
                  this->set_url();
                  return;
            }

#pragma endregion

            /* Returns protocol string */
            std::string get_protocol_str() {
                  return protocol_str(this->protocol);
            }

            /* Tests proxy, returns status code. */
            std::size_t test(const std::size_t mili = 700u /* Time out in miliseconds. */) {
                  cpr::Session session;
                  this->cpr(session);
                  session.SetUrl(cpr::Url(this->url));
                  session.SetTimeout(cpr::Timeout(static_cast<std::int32_t>(mili)));
                  const auto result = session.Get();
                  this->ping = result.elapsed;
                  return result.status_code;
            }

          private:
            /* Set */
            void set_url() {
                  this->url = this->get_protocol_str() + "://" + this->ip + ":" + this->port;
                  return;
            }
      };

} // namespace cpr_proxy_manager

#endif /* cpr_proxy_manage */