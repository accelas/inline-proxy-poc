#pragma once

#include <sys/socket.h>
#include <sys/types.h>

#include "shared/scoped_fd.hpp"

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

namespace inline_proxy {

using SetSockOptHook = int (*)(int fd, int level, int optname, const void* optval, socklen_t optlen);
using BindHook = int (*)(int fd, const sockaddr* addr, socklen_t addrlen);
using ConnectHook = int (*)(int fd, const sockaddr* addr, socklen_t addrlen);
using FcntlHook = int (*)(int fd, int cmd, int arg);

struct TransparentConnectResult {
    ScopedFd fd;
    bool connecting = false;

    bool ok() const noexcept;
    explicit operator bool() const noexcept;
};

void SetSetSockOptHookForTesting(SetSockOptHook hook);
void SetBindHookForTesting(BindHook hook);
void SetConnectHookForTesting(ConnectHook hook);
void SetFcntlHookForTesting(FcntlHook hook);

int DoSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen);
int DoBind(int fd, const sockaddr* addr, socklen_t addrlen);
int DoConnect(int fd, const sockaddr* addr, socklen_t addrlen);
int DoFcntl(int fd, int cmd, int arg);

sockaddr_storage GetPeer(int fd);
sockaddr_storage GetSockName(int fd);
TransparentConnectResult CreateTransparentSocket(const sockaddr_storage& original_src,
                                                 const sockaddr_storage& original_dst);
bool SetNonBlocking(int fd);

}  // namespace inline_proxy
