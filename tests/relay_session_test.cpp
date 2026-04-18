#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <sys/poll.h>
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
std::optional<ssize_t> g_send_result;
int g_last_send_flags = 0;

class HookScope {
public:
    HookScope() = default;
    ~HookScope() {
        inline_proxy::SetSetSockOptHookForTesting(nullptr);
        inline_proxy::SetSendHookForTesting(nullptr);
        inline_proxy::SetShutdownHookForTesting(nullptr);
        g_fake_transparent_options = false;
        g_send_result.reset();
        g_last_send_flags = 0;
    }
};

int TestSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    if (level == IPPROTO_IP && (optname == IP_TRANSPARENT || optname == IP_FREEBIND) &&
        g_fake_transparent_options) {
        return 0;
    }
    return ::setsockopt(fd, level, optname, optval, optlen);
}

ssize_t RecordingSend(int fd, const void* buffer, size_t length, int flags) {
    g_last_send_flags = flags;
    if (g_send_result.has_value()) {
        errno = EAGAIN;
        return *g_send_result;
    }
    return ::send(fd, buffer, length, flags);
}

struct TcpListener {
    inline_proxy::ScopedFd fd;
    sockaddr_storage addr{};
};

TcpListener MakeTcpListener(const std::string& ip) {
    TcpListener listener;
    listener.fd.reset(::socket(AF_INET, SOCK_STREAM, 0));
    if (!listener.fd) {
        ADD_FAILURE() << "failed to create listener socket";
        return listener;
    }

    const int reuse = 1;
    if (::setsockopt(listener.fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        ADD_FAILURE() << "failed to set SO_REUSEADDR";
        listener.fd.reset();
        return listener;
    }

    listener.addr = inline_proxy::MakeSockaddr4(ip, 0);
    if (::bind(listener.fd.get(), reinterpret_cast<sockaddr*>(&listener.addr), sizeof(sockaddr_in)) != 0) {
        ADD_FAILURE() << "failed to bind listener";
        listener.fd.reset();
        return listener;
    }
    if (::listen(listener.fd.get(), 4) != 0) {
        ADD_FAILURE() << "failed to listen";
        listener.fd.reset();
        return listener;
    }

    listener.addr = inline_proxy::GetSockName(listener.fd.get());
    return listener;
}

ssize_t WriteAll(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t written = 0;
    while (written < size) {
        const ssize_t n = ::write(fd, bytes + written, size - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return n;
        }
        written += static_cast<std::size_t>(n);
    }
    return static_cast<ssize_t>(written);
}

std::string ReadWithTimeout(int fd) {
    pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
    if (::poll(&pfd, 1, 1000) != 1) {
        return {};
    }
    char buffer[64] = {};
    const ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n <= 0) {
        return {};
    }
    return std::string(buffer, buffer + n);
}

bool ReadEofWithTimeout(int fd) {
    pollfd pfd{.fd = fd, .events = POLLIN | POLLRDHUP | POLLHUP, .revents = 0};
    if (::poll(&pfd, 1, 1000) != 1) {
        return false;
    }
    char byte = 0;
    const ssize_t n = ::read(fd, &byte, sizeof(byte));
    return n == 0;
}

}  // namespace

TEST(RelaySessionTest, RelaysBytesBetweenClientAndUpstreamServer) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    auto upstream = MakeTcpListener("127.0.0.1");
    auto proxy_listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(proxy_listener.ok());

    std::promise<void> upstream_accepted;
    std::promise<void> upstream_done;
    std::thread upstream_thread([&] {
        int accepted_fd = ::accept(upstream.fd.get(), nullptr, nullptr);
        ASSERT_GE(accepted_fd, 0);
        inline_proxy::ScopedFd accepted(accepted_fd);
        upstream_accepted.set_value();

        char buffer[64] = {};
        const ssize_t n = ::read(accepted.get(), buffer, sizeof(buffer));
        ASSERT_GT(n, 0);
        ASSERT_EQ(WriteAll(accepted.get(), buffer, static_cast<std::size_t>(n)), n);
        upstream_done.set_value();
    });

    const auto proxy_addr = inline_proxy::GetSockName(proxy_listener.fd());
    ASSERT_EQ(proxy_addr.ss_family, AF_INET);

    inline_proxy::ScopedFd client(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_TRUE(client);
    ASSERT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&proxy_addr), sizeof(sockaddr_in)), 0);

    int accepted_fd = ::accept(proxy_listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    inline_proxy::SessionEndpoints endpoints{
        .client = inline_proxy::MakeSockaddr4("127.0.0.1", 0),
        .original_dst = upstream.addr,
    };

    inline_proxy::EventLoop loop;
    auto session = inline_proxy::CreateRelaySession(loop, std::move(accepted), endpoints);
    ASSERT_TRUE(session);

    std::thread loop_thread([&] { loop.Run(); });

    ASSERT_EQ(upstream_accepted.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "upstream server never accepted the transparent connection";

    const std::string payload = "relay-check";
    ASSERT_EQ(WriteAll(client.get(), payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));

    const std::string echoed = ReadWithTimeout(client.get());
    EXPECT_EQ(echoed, payload);

    client.reset();
    loop.Stop();
    loop_thread.join();
    session.reset();
    upstream_thread.join();
    ASSERT_EQ(upstream_done.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "upstream server never observed echoed data";
}

TEST(RelaySessionTest, UsesNoSignalSocketWrites) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);
    inline_proxy::SetSendHookForTesting(RecordingSend);

    auto upstream = MakeTcpListener("127.0.0.1");
    auto proxy_listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(proxy_listener.ok());

    std::promise<void> upstream_accepted;
    std::thread upstream_thread([&] {
        int accepted_fd = ::accept(upstream.fd.get(), nullptr, nullptr);
        ASSERT_GE(accepted_fd, 0);
        inline_proxy::ScopedFd accepted(accepted_fd);
        upstream_accepted.set_value();

        char buffer[64] = {};
        const ssize_t n = ::read(accepted.get(), buffer, sizeof(buffer));
        ASSERT_GT(n, 0);
        ASSERT_EQ(WriteAll(accepted.get(), buffer, static_cast<std::size_t>(n)), n);
    });

    const auto proxy_addr = inline_proxy::GetSockName(proxy_listener.fd());
    inline_proxy::ScopedFd client(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_TRUE(client);
    ASSERT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&proxy_addr), sizeof(sockaddr_in)), 0);

    int accepted_fd = ::accept(proxy_listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    inline_proxy::SessionEndpoints endpoints{
        .client = inline_proxy::MakeSockaddr4("127.0.0.1", 0),
        .original_dst = upstream.addr,
    };

    inline_proxy::EventLoop loop;
    auto session = inline_proxy::CreateRelaySession(loop, std::move(accepted), endpoints);
    ASSERT_TRUE(session);

    std::thread loop_thread([&] { loop.Run(); });
    ASSERT_EQ(upstream_accepted.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready);

    const std::string payload = "no-signal";
    ASSERT_EQ(WriteAll(client.get(), payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(ReadWithTimeout(client.get()), payload);
    EXPECT_NE(g_last_send_flags & MSG_NOSIGNAL, 0);

    client.reset();
    loop.Stop();
    loop_thread.join();
    session.reset();
    upstream_thread.join();
}

TEST(RelaySessionTest, PropagatesUpstreamEofToClient) {
    HookScope hooks;
    g_fake_transparent_options = true;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);

    auto upstream = MakeTcpListener("127.0.0.1");
    auto proxy_listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(proxy_listener.ok());

    std::promise<void> upstream_accepted;
    std::thread upstream_thread([&] {
        int accepted_fd = ::accept(upstream.fd.get(), nullptr, nullptr);
        ASSERT_GE(accepted_fd, 0);
        inline_proxy::ScopedFd accepted(accepted_fd);
        upstream_accepted.set_value();

        char buffer[64] = {};
        const ssize_t n = ::read(accepted.get(), buffer, sizeof(buffer));
        ASSERT_GT(n, 0);
        ASSERT_EQ(WriteAll(accepted.get(), buffer, static_cast<std::size_t>(n)), n);
        ASSERT_EQ(::shutdown(accepted.get(), SHUT_WR), 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });

    const auto proxy_addr = inline_proxy::GetSockName(proxy_listener.fd());
    inline_proxy::ScopedFd client(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_TRUE(client);
    ASSERT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&proxy_addr), sizeof(sockaddr_in)), 0);

    int accepted_fd = ::accept(proxy_listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    inline_proxy::SessionEndpoints endpoints{
        .client = inline_proxy::MakeSockaddr4("127.0.0.1", 0),
        .original_dst = upstream.addr,
    };

    inline_proxy::EventLoop loop;
    auto session = inline_proxy::CreateRelaySession(loop, std::move(accepted), endpoints);
    ASSERT_TRUE(session);

    std::thread loop_thread([&] { loop.Run(); });
    ASSERT_EQ(upstream_accepted.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready);

    const std::string payload = "half-close";
    ASSERT_EQ(WriteAll(client.get(), payload.data(), payload.size()), static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(ReadWithTimeout(client.get()), payload);
    EXPECT_TRUE(ReadEofWithTimeout(client.get()));

    client.reset();
    loop.Stop();
    loop_thread.join();
    session.reset();
    upstream_thread.join();
}

TEST(RelaySessionTest, AppliesBackpressureWhenUpstreamWriteStalls) {
    HookScope hooks;
    g_fake_transparent_options = true;
    g_send_result = -1;
    inline_proxy::SetSetSockOptHookForTesting(TestSetSockOpt);
    inline_proxy::SetSendHookForTesting(RecordingSend);

    auto upstream = MakeTcpListener("127.0.0.1");
    auto proxy_listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(proxy_listener.ok());

    std::promise<void> upstream_accepted;
    std::thread upstream_thread([&] {
        int accepted_fd = ::accept(upstream.fd.get(), nullptr, nullptr);
        ASSERT_GE(accepted_fd, 0);
        inline_proxy::ScopedFd accepted(accepted_fd);
        upstream_accepted.set_value();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });

    const auto proxy_addr = inline_proxy::GetSockName(proxy_listener.fd());
    inline_proxy::ScopedFd client(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_TRUE(client);
    const int small_sendbuf = 4096;
    ASSERT_EQ(::setsockopt(client.get(), SOL_SOCKET, SO_SNDBUF, &small_sendbuf, sizeof(small_sendbuf)), 0);
    ASSERT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&proxy_addr), sizeof(sockaddr_in)), 0);
    ASSERT_TRUE(inline_proxy::SetNonBlocking(client.get()));

    int accepted_fd = ::accept(proxy_listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);
    const int small_recvbuf = 4096;
    ASSERT_EQ(::setsockopt(accepted.get(), SOL_SOCKET, SO_RCVBUF, &small_recvbuf, sizeof(small_recvbuf)), 0);

    inline_proxy::SessionEndpoints endpoints{
        .client = inline_proxy::MakeSockaddr4("127.0.0.1", 0),
        .original_dst = upstream.addr,
    };

    inline_proxy::EventLoop loop;
    auto session = inline_proxy::CreateRelaySession(loop, std::move(accepted), endpoints);
    ASSERT_TRUE(session);

    std::thread loop_thread([&] { loop.Run(); });
    ASSERT_EQ(upstream_accepted.get_future().wait_for(std::chrono::seconds(1)), std::future_status::ready);

    std::string payload(inline_proxy::RelaySessionBufferHighWaterMark() * 8, 'x');
    std::size_t written = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (written < payload.size() && std::chrono::steady_clock::now() < deadline) {
        const ssize_t n = ::write(client.get(), payload.data() + written, payload.size() - written);
        if (n > 0) {
            written += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        FAIL() << "client write failed: " << std::strerror(errno);
    }

    EXPECT_LT(written, payload.size());

    client.reset();
    loop.Stop();
    loop_thread.join();
    session.reset();
    upstream_thread.join();
}
