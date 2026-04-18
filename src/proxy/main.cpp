#include "proxy/config.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        inline_proxy::ProxyConfig cfg = inline_proxy::ProxyConfig::FromArgs(argc, argv);
        return inline_proxy::RunProxyDaemon(cfg);
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }
}
