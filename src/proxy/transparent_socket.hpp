#pragma once

#include <sys/socket.h>

#include "proxy/transparent_listener.hpp"

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

namespace inline_proxy {

sockaddr_storage GetPeer(int fd);
sockaddr_storage GetSockName(int fd);
ScopedFd CreateTransparentSocket(const sockaddr_storage& original_src,
                                 const sockaddr_storage& original_dst);
bool SetNonBlocking(int fd);

}  // namespace inline_proxy
