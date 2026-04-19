#include "shared/sockaddr.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <cstring>

namespace inline_proxy {

sockaddr_storage MakeSockaddr4(const std::string& address, std::uint16_t port) {
    sockaddr_storage storage{};
    auto* addr4 = reinterpret_cast<sockaddr_in*>(&storage);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    if (::inet_pton(AF_INET, address.c_str(), &addr4->sin_addr) != 1) {
        storage.ss_family = AF_UNSPEC;
    }
    return storage;
}

std::string FormatSockaddr(const sockaddr_storage& addr) {
    if (addr.ss_family != AF_INET) {
        return {};
    }

    const auto* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
    std::array<char, INET_ADDRSTRLEN> ip{};
    if (::inet_ntop(AF_INET, &addr4->sin_addr, ip.data(), ip.size()) == nullptr) {
        return {};
    }

    return std::string(ip.data()) + ":" + std::to_string(ntohs(addr4->sin_port));
}

}  // namespace inline_proxy
