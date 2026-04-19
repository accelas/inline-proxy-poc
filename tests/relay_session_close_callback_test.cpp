#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

#include "proxy/relay_session.hpp"
#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"

namespace {

bool g_fake_transparent_options = false;

class HookScope {
public:
    ~HookScope() {
        inline_proxy::SetSetSockOptHookForTesting(nullptr);
        g_fake_transparent_options = false;
    }
};

int TestSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    if (level == IPPROTO_IP && (optname == IP_TRANSPARENT || optname == IP_FREEBIND) &&
        g_fake_transparent_options) {
        return 0;
    }
    return ::setsockopt(fd, level, optname, optval, optlen);
}

struct TcpListener {
    inline_proxy::ScopedFd fd;
    sockaddr_storage addr{};
};

TcpListener MakeTcpListener(const std::string& ip) {
    TcpListener listener;
    listener.fd.reset(::socket(AF_INET, SOCK_STREAM, 0));
    EXPECT_TRUE(listener.fd);
    const int reuse = 1;
    EXPECT_EQ(::setsockopt(listener.fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), 0);
    listener.addr = inline_proxy::MakeSockaddr4(ip, 0);
    EXPECT_EQ(::bind(listener.fd.get(), reinterpret_cast<sockaddr*>(&listener.addr), sizeof(sockaddr_in)), 0);
    EXPECT_EQ(::listen(listener.fd.get(), 4), 0);
    listener.addr = inline_proxy::GetSockName(listener.fd.get());
    return listener;
}

}  // namespace

TEST(RelaySessionTest, CloseCallbackRunsWhenSessionTerminates) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    auto upstream = MakeTcpListener("127.0.0.1");
    ASSERT_TRUE(upstream.fd);

    auto proxy_listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(proxy_listener.ok());
    const auto proxy_addr = inline_proxy::GetSockName(proxy_listener.fd());

    inline_proxy::ScopedFd client(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_TRUE(client);
    ASSERT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&proxy_addr), sizeof(sockaddr_in)), 0);

    int accepted_fd = ::accept(proxy_listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    std::promise<void> upstream_accepted;
    std::thread upstream_thread([&] {
        int connected_fd = ::accept(upstream.fd.get(), nullptr, nullptr);
        ASSERT_GE(connected_fd, 0);
        inline_proxy::ScopedFd connected(connected_fd);
        upstream_accepted.set_value();
    });

    std::atomic<int> close_calls{0};
    inline_proxy::SessionEndpoints endpoints{
        .client = inline_proxy::MakeSockaddr4("127.0.0.1", 0),
        .original_dst = upstream.addr,
    };

    inline_proxy::EventLoop loop;
    auto session = inline_proxy::CreateRelaySession(
        loop, std::move(accepted), endpoints,
        [&] { ++close_calls; });
    ASSERT_TRUE(session);

    ASSERT_EQ(upstream_accepted.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready);

    session.reset();
    upstream_thread.join();
    EXPECT_EQ(close_calls.load(), 1);
}
