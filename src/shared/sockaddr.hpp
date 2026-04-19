#pragma once

#include <cstdint>
#include <string>
#include <sys/socket.h>

namespace inline_proxy {

sockaddr_storage MakeSockaddr4(const std::string& address, std::uint16_t port);
std::string FormatSockaddr(const sockaddr_storage& addr);

}  // namespace inline_proxy
