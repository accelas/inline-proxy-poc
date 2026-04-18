#include <gtest/gtest.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "proxy/config.hpp"
#include "shared/scoped_fd.hpp"

namespace {

int g_last_flags = 0;

ssize_t RecordingSend(int fd, const void* buffer, size_t length, int flags) {
    g_last_flags = flags;
    return ::send(fd, buffer, length, 0);
}

class HookScope {
public:
    HookScope() {
        inline_proxy::SetAdminSendHookForTesting(RecordingSend);
    }

    ~HookScope() {
        inline_proxy::SetAdminSendHookForTesting(nullptr);
        g_last_flags = 0;
    }
};

}  // namespace

TEST(AdminConnectionSendTest, WritesWithNoSigpipeFlag) {
    HookScope scope;

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    inline_proxy::ScopedFd left(fds[0]);
    inline_proxy::ScopedFd right(fds[1]);
    (void)right;

    const std::string payload = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    EXPECT_GE(inline_proxy::DoAdminSend(left.get(), payload.data(), payload.size(), MSG_NOSIGNAL), 0);
    EXPECT_NE(g_last_flags & MSG_NOSIGNAL, 0);
}
