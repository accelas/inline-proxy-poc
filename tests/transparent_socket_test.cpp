#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"

namespace {

bool g_fake_transparent_options = false;
int g_failing_socket_option = -1;
bool g_bind_should_fail = false;
std::vector<std::string>* g_call_log = nullptr;

class HookScope {
public:
    HookScope() = default;
    ~HookScope() {
        inline_proxy::SetSetSockOptHookForTesting(nullptr);
        inline_proxy::SetBindHookForTesting(nullptr);
        inline_proxy::SetConnectHookForTesting(nullptr);
        inline_proxy::SetFcntlHookForTesting(nullptr);
        g_fake_transparent_options = false;
        g_failing_socket_option = -1;
        g_bind_should_fail = false;
        g_call_log = nullptr;
    }
};

int TestSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    if (level == IPPROTO_IP && (optname == IP_TRANSPARENT || optname == IP_FREEBIND)) {
        if (optname == g_failing_socket_option) {
            errno = EPERM;
            return -1;
        }
        if (g_fake_transparent_options) {
            return 0;
        }
    }
    return ::setsockopt(fd, level, optname, optval, optlen);
}

int TestBind(int fd, const sockaddr* addr, socklen_t addrlen) {
    if (g_bind_should_fail) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    return ::bind(fd, addr, addrlen);
}

int RecordingBind(int fd, const sockaddr*, socklen_t) {
    if (g_call_log != nullptr) {
        g_call_log->push_back("bind");
    }
    return 0;
}

int RecordingConnect(int, const sockaddr*, socklen_t) {
    if (g_call_log != nullptr) {
        g_call_log->push_back("connect");
    }
    return 0;
}

int InProgressConnect(int, const sockaddr*, socklen_t) {
    errno = EINPROGRESS;
    return -1;
}

int RecordingFcntl(int fd, int cmd, int arg) {
    if (cmd == F_SETFL && (arg & O_NONBLOCK) != 0 && g_call_log != nullptr) {
        g_call_log->push_back("set-nonblocking");
    }
    switch (cmd) {
        case F_GETFL:
            return ::fcntl(fd, cmd);
        default:
            return ::fcntl(fd, cmd, arg);
    }
}

inline_proxy::ScopedFd MakeClientSocket(const sockaddr_storage& addr) {
    inline_proxy::ScopedFd sock(::socket(AF_INET, SOCK_STREAM, 0));
    if (!sock) {
        return sock;
    }
    const int reuse = 1;
    ::setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in)) != 0) {
        return inline_proxy::ScopedFd();
    }
    return sock;
}

}  // namespace

TEST(TransparentSocketTest, ListenerFailsWhenRequiredTransparentOptionCannotBeEnabled) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    for (int optname : {IP_TRANSPARENT, IP_FREEBIND}) {
        g_failing_socket_option = optname;
        auto listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
        EXPECT_FALSE(listener.ok()) << "listener unexpectedly succeeded when opt " << optname << " failed";
    }
}

TEST(TransparentSocketTest, TransparentListenerIsNonBlocking) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    auto listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(listener.ok());

    const int flags = ::fcntl(listener.fd(), F_GETFL, 0);
    ASSERT_GE(flags, 0);
    EXPECT_NE(flags & O_NONBLOCK, 0) << "transparent listener must be nonblocking";
}

TEST(TransparentSocketTest, AcceptedSocketHelpersReportPeerAndLocalAddresses) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    auto listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(listener.ok());

    const auto listener_addr = inline_proxy::GetSockName(listener.fd());
    ASSERT_EQ(listener_addr.ss_family, AF_INET);

    auto client = MakeClientSocket(listener_addr);
    ASSERT_TRUE(client);

    const int accepted_fd = ::accept(listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    const auto peer = inline_proxy::GetPeer(accepted.get());
    const auto local = inline_proxy::GetSockName(accepted.get());
    const auto client_local = inline_proxy::GetSockName(client.get());

    EXPECT_EQ(inline_proxy::FormatSockaddr(peer), inline_proxy::FormatSockaddr(client_local));
    EXPECT_EQ(inline_proxy::FormatSockaddr(local), inline_proxy::FormatSockaddr(listener_addr));
}

TEST(TransparentSocketTest, TransparentSocketFailsWhenRequiredTransparentOptionCannotBeEnabled) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    const auto src = inline_proxy::MakeSockaddr4("127.0.0.1", 0);
    const auto dst = inline_proxy::MakeSockaddr4("127.0.0.1", 8080);

    for (int optname : {IP_TRANSPARENT, IP_FREEBIND}) {
        g_failing_socket_option = optname;
        auto result = inline_proxy::CreateTransparentSocket(src, dst);
        EXPECT_FALSE(result.ok()) << "socket unexpectedly succeeded when opt " << optname << " failed";
    }
}

TEST(TransparentSocketTest, TransparentSocketFailsWhenBindFails) {
    HookScope hooks;
    g_fake_transparent_options = true;
    g_bind_should_fail = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);
    inline_proxy::SetBindHookForTesting(TestBind);

    const auto src = inline_proxy::MakeSockaddr4("127.0.0.1", 0);
    const auto dst = inline_proxy::MakeSockaddr4("127.0.0.1", 8080);

    auto result = inline_proxy::CreateTransparentSocket(src, dst);
    EXPECT_FALSE(result.ok());
}

TEST(TransparentSocketTest, TransparentSocketSetsNonBlockingBeforeConnect) {
    HookScope hooks;
    g_fake_transparent_options = true;
    std::vector<std::string> call_log;
    g_call_log = &call_log;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);
    inline_proxy::SetBindHookForTesting(RecordingBind);
    inline_proxy::SetConnectHookForTesting(RecordingConnect);
    inline_proxy::SetFcntlHookForTesting(RecordingFcntl);

    const auto src = inline_proxy::MakeSockaddr4("127.0.0.1", 0);
    const auto dst = inline_proxy::MakeSockaddr4("127.0.0.1", 8080);

    auto result = inline_proxy::CreateTransparentSocket(src, dst);
    ASSERT_TRUE(result.ok());
    ASSERT_GE(result.fd.get(), 0);

    const auto nonblocking_it = std::find(call_log.begin(), call_log.end(), "set-nonblocking");
    const auto connect_it = std::find(call_log.begin(), call_log.end(), "connect");
    ASSERT_NE(nonblocking_it, call_log.end());
    ASSERT_NE(connect_it, call_log.end());
    EXPECT_LT(nonblocking_it, connect_it);
}

TEST(TransparentSocketTest, TransparentSocketReportsNonblockingConnectInProgress) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);
    inline_proxy::SetBindHookForTesting(RecordingBind);
    inline_proxy::SetConnectHookForTesting(InProgressConnect);

    const auto src = inline_proxy::MakeSockaddr4("127.0.0.1", 0);
    const auto dst = inline_proxy::MakeSockaddr4("127.0.0.1", 8080);

    auto result = inline_proxy::CreateTransparentSocket(src, dst);
    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.connecting);
}
