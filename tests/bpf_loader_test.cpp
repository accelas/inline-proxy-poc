#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <system_error>
#include <unistd.h>
#include <utility>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "bpf/ingress_redirect_common.h"
#include "bpf/loader.hpp"

TEST(BpfLoaderTest, RejectsMissingInterfaceName) {
    inline_proxy::BpfLoader loader;
    EXPECT_FALSE(loader.AttachIngress(""));
}

TEST(BpfLoaderTest, RejectsNonWanInterfaceNamesAfterListenerConfiguration) {
    inline_proxy::BpfLoader loader;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    EXPECT_TRUE(loader.ConfigureListenerSocket(listener_fd));

    EXPECT_FALSE(loader.AttachIngress("lan_eth1"));
    EXPECT_FALSE(loader.IsIngressAttached("lan_eth1"));

    ::close(listener_fd);
}

TEST(BpfLoaderTest, CapturesListenerPortFromConfiguredSocket) {
    inline_proxy::BpfLoader loader;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    socklen_t len = sizeof(addr);
    ASSERT_EQ(::getsockname(listener_fd, reinterpret_cast<sockaddr*>(&addr), &len), 0);
    const std::uint16_t expected_port = ntohs(addr.sin_port);

    EXPECT_TRUE(loader.ConfigureListenerSocket(listener_fd));
    EXPECT_EQ(loader.listener_port(), expected_port);

    ::close(listener_fd);
}

TEST(BpfLoaderTest, RejectsConfigureListenerSocketWhenGetsocknameFails) {
    inline_proxy::BpfLoader loader;

    int pipe_fds[2];
    ASSERT_EQ(::pipe(pipe_fds), 0);

    EXPECT_FALSE(loader.ConfigureListenerSocket(pipe_fds[0]));
    EXPECT_FALSE(loader.listener_socket_fd().has_value());
    EXPECT_EQ(loader.listener_port(), 0U);

    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
}

TEST(BpfLoaderTest, LoadsSkeleton) {
    if (::geteuid() != 0) {
        GTEST_SKIP() << "Requires root / CAP_BPF";
    }
    inline_proxy::BpfLoader loader;
    EXPECT_TRUE(loader.LoadProgramForTesting());
}

namespace {

std::string MakeTempPinDir() {
    char tmpl[] = "/sys/fs/bpf/bpf-loader-test-XXXXXX";
    if (::mkdtemp(tmpl) == nullptr) {
        return {};
    }
    return tmpl;
}

class TempPinDir {
public:
    explicit TempPinDir(std::string dir) : dir_(std::move(dir)) {}
    ~TempPinDir() {
        if (!dir_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(dir_, ec);
        }
    }
    TempPinDir(const TempPinDir&) = delete;
    TempPinDir& operator=(const TempPinDir&) = delete;
    const std::string& path() const { return dir_; }
private:
    std::string dir_;
};

}  // namespace

TEST(BpfLoaderTest, LoadAndPinCreatesPins) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    TempPinDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    const auto& dir = guard.path();
    inline_proxy::BpfLoader loader;
    EXPECT_TRUE(loader.LoadAndPin(dir));
    EXPECT_TRUE(std::filesystem::exists(dir + "/prog"));
    EXPECT_TRUE(std::filesystem::exists(dir + "/config_map"));
    EXPECT_TRUE(std::filesystem::exists(dir + "/listener_map"));
}

TEST(BpfLoaderTest, LoadAndPinIsIdempotent) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    TempPinDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    const auto& dir = guard.path();
    {
        inline_proxy::BpfLoader loader;
        EXPECT_TRUE(loader.LoadAndPin(dir));
    }
    {
        inline_proxy::BpfLoader loader;
        EXPECT_TRUE(loader.LoadAndPin(dir));
        EXPECT_TRUE(std::filesystem::exists(dir + "/prog"));
    }
}

TEST(BpfLoaderTest, LoadAndPinReusesPinOnTagMatch) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    TempPinDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    const auto& dir = guard.path();
    auto read_prog_id = [&](const std::string& prog_path) -> std::uint32_t {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<__u64>(prog_path.c_str());
        int fd = static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
        if (fd < 0) return 0;
        struct bpf_prog_info info{};
        std::memset(&info, 0, sizeof(info));
        std::uint32_t info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
            ::close(fd);
            return 0;
        }
        ::close(fd);
        return info.id;
    };

    inline_proxy::BpfLoader first;
    ASSERT_TRUE(first.LoadAndPin(dir));
    const std::uint32_t first_id = read_prog_id(dir + "/prog");
    ASSERT_NE(first_id, 0u);

    inline_proxy::BpfLoader second;
    ASSERT_TRUE(second.LoadAndPin(dir));
    const std::uint32_t second_id = read_prog_id(dir + "/prog");
    EXPECT_EQ(first_id, second_id) << "tag-match reuse should keep prog id stable";
}

TEST(BpfLoaderTest, WriteConfigPopulatesConfigMap) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    TempPinDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    const auto& dir = guard.path();
    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.LoadAndPin(dir));
    EXPECT_TRUE(loader.WriteConfig(15001, 0x100));
    union bpf_attr get_attr{};
    std::memset(&get_attr, 0, sizeof(get_attr));
    const std::string map_path = dir + "/config_map";
    get_attr.pathname = reinterpret_cast<__u64>(map_path.c_str());
    int map_fd = static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &get_attr, sizeof(get_attr)));
    ASSERT_GE(map_fd, 0);
    IngressRedirectConfig cfg{};
    union bpf_attr lookup_attr{};
    std::memset(&lookup_attr, 0, sizeof(lookup_attr));
    std::uint32_t key = 0;
    lookup_attr.map_fd = static_cast<__u32>(map_fd);
    lookup_attr.key = reinterpret_cast<__u64>(&key);
    lookup_attr.value = reinterpret_cast<__u64>(&cfg);
    ASSERT_EQ(::syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)), 0);
    EXPECT_EQ(cfg.enabled, 1);
    EXPECT_EQ(cfg.listener_port, 15001u);
    EXPECT_EQ(cfg.skb_mark, 0x100u);
    ::close(map_fd);
}

TEST(BpfLoaderTest, WriteListenerFdAcceptsListeningSocket) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    TempPinDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    const auto& dir = guard.path();
    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.LoadAndPin(dir));
    const int sock = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(sock, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(sock, 16), 0);
    EXPECT_TRUE(loader.WriteListenerFd(sock));
    ::close(sock);
}
