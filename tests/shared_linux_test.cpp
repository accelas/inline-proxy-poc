#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"
#include "shared/state_store.hpp"

TEST(SockaddrTest, FormatsIpv4Endpoint) {
    auto addr = inline_proxy::MakeSockaddr4("10.42.0.15", 8080);
    EXPECT_EQ(inline_proxy::FormatSockaddr(addr), "10.42.0.15:8080");
}

TEST(ScopedFdTest, ClosesFdOnDestruction) {
    int fd = ::dup(STDOUT_FILENO);
    ASSERT_GE(fd, 0);

    {
        inline_proxy::ScopedFd scoped(fd);
        EXPECT_TRUE(scoped);
        EXPECT_EQ(scoped.get(), fd);
    }

    const int rc = ::fcntl(fd, F_GETFD);
    const int err = errno;
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(err, EBADF);
}

TEST(StateStoreTest, RoundTripsFlatJson) {
    const auto path = std::filesystem::temp_directory_path() / "inline_proxy_state_store_test.json";
    std::error_code ec;
    std::filesystem::remove(path, ec);

    inline_proxy::StateStore store(path);
    inline_proxy::StateFields fields{{"pod_uid", "abc123"}, {"wan_ifname", "wan0"}};
    ASSERT_TRUE(store.Write(fields));

    auto loaded = store.Read();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, fields);
    EXPECT_TRUE(store.Remove());
    EXPECT_TRUE(store.Remove());
}
