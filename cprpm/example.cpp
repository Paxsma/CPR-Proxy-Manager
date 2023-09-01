#include "cpr_proxy_manager/proxy_manager.hpp"
#include <iostream>

std::int32_t main() {

      /* Make proxy pointer and set it to socks5 proxy: "174.64.199.79:4145" */
      auto proxy = std::make_shared<cpr_proxy_manager::proxy>();
      proxy->load("174.64.199.79", "4145", cpr_proxy_manager::protocols::socks5);

      /* Set session to example.com */
      cpr::Session session;
      proxy->cpr(session);
      session.SetUrl(cpr::Url("https://example.com/"));

      /* Get and print status code */
      std::cout << "example.com return status code " << session.Get().status_code << std::endl;
      std::cin.get();

      return 1;
}