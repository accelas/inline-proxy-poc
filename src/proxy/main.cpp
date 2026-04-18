#include "proxy/config.hpp"

int main(int argc, char** argv) {
    inline_proxy::ProxyConfig cfg = inline_proxy::ProxyConfig::FromEnv(argc, argv);
    return inline_proxy::RunProxyDaemon(cfg);
}
