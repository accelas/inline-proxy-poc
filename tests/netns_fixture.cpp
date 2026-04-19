#include "tests/netns_fixture.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "cni/splice_executor.hpp"
#include "cni/splice_plan.hpp"
#include "cni/yajl_parser.hpp"
#include "proxy/relay_session.hpp"
#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/netlink.hpp"
#include "shared/netns.hpp"
#include "shared/scoped_fd.hpp"

namespace inline_proxy {
namespace {

constexpr std::chrono::seconds kIoTimeout(5);
constexpr unsigned int kCapNetAdminBit = 12;

std::string NamespacePath(const std::string& name) {
    return "/var/run/netns/" + name;
}

std::string Quote(const std::string& value) {
    return "'" + value + "'";
}

std::string ShortIfName(const std::string& prefix, std::string_view suffix) {
    std::string ifname = prefix + std::string(suffix);
    if (ifname.size() > 15) {
        ifname.resize(15);
    }
    return ifname;
}

bool HasCapNetAdmin() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("CapEff:\t", 0) != 0) {
            continue;
        }
        const auto hex_caps = line.substr(sizeof("CapEff:\t") - 1);
        unsigned long long capabilities = 0;
        try {
            capabilities = std::stoull(hex_caps, nullptr, 16);
        } catch (...) {
            return false;
        }
        return (capabilities & (1ULL << kCapNetAdminBit)) != 0;
    }
    return false;
}

bool WaitForReadable(int fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    return ::poll(&descriptor, 1, static_cast<int>(timeout.count())) > 0 &&
           (descriptor.revents & POLLIN) != 0;
}

ScopedFd AcceptWithTimeout(int fd, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!WaitForReadable(fd, std::chrono::milliseconds(100))) {
            continue;
        }
        ScopedFd accepted(::accept4(fd, nullptr, nullptr, SOCK_CLOEXEC));
        if (accepted) {
            return accepted;
        }
    }
    return {};
}

bool SendAll(int fd, const std::string& payload) {
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const ssize_t written = ::send(fd,
                                       payload.data() + offset,
                                       payload.size() - offset,
                                       MSG_NOSIGNAL);
        if (written <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

std::optional<std::string> ReadExact(int fd, std::size_t expected) {
    std::string output;
    output.resize(expected);
    std::size_t offset = 0;
    while (offset < expected) {
        const ssize_t n = ::recv(fd, output.data() + offset, expected - offset, 0);
        if (n <= 0) {
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(n);
    }
    return output;
}

bool ConnectAndRoundTrip(const std::string& netns_path,
                         const std::string& address,
                         std::uint16_t port,
                         const std::string& payload,
                         std::string* reply) {
    auto entered = ScopedNetns::Enter(netns_path);
    if (!entered) {
        return false;
    }

    ScopedFd fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!fd) {
        return false;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (::inet_pton(AF_INET, address.c_str(), &server.sin_addr) != 1) {
        return false;
    }

    if (::connect(fd.get(), reinterpret_cast<sockaddr*>(&server), sizeof(server)) != 0) {
        return false;
    }
    if (!SendAll(fd.get(), payload)) {
        return false;
    }
    ::shutdown(fd.get(), SHUT_WR);

    const auto response = ReadExact(fd.get(), payload.size());
    if (!response.has_value()) {
        return false;
    }
    if (reply) {
        *reply = *response;
    }
    return true;
}

std::optional<std::string> RunEchoServer(const std::string& netns_path,
                                         const std::string& address,
                                         std::uint16_t port,
                                         const std::string& expected_payload) {
    auto entered = ScopedNetns::Enter(netns_path);
    if (!entered) {
        return std::nullopt;
    }

    ScopedFd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!listener) {
        return std::nullopt;
    }

    const int reuse = 1;
    if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        return std::nullopt;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (::inet_pton(AF_INET, address.c_str(), &server.sin_addr) != 1) {
        return std::nullopt;
    }

    if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&server), sizeof(server)) != 0) {
        return std::nullopt;
    }
    if (::listen(listener.get(), 8) != 0) {
        return std::nullopt;
    }

    ScopedFd accepted = AcceptWithTimeout(listener.get(), std::chrono::duration_cast<std::chrono::milliseconds>(kIoTimeout));
    if (!accepted) {
        return std::nullopt;
    }

    char peer_buffer[INET_ADDRSTRLEN] = {};
    sockaddr_storage peer = GetPeer(accepted.get());
    if (peer.ss_family != AF_INET ||
        ::inet_ntop(AF_INET,
                    &reinterpret_cast<const sockaddr_in&>(peer).sin_addr,
                    peer_buffer,
                    sizeof(peer_buffer)) == nullptr) {
        return std::nullopt;
    }

    const auto request = ReadExact(accepted.get(), expected_payload.size());
    if (!request.has_value() || *request != expected_payload) {
        return std::nullopt;
    }
    if (!SendAll(accepted.get(), *request)) {
        return std::nullopt;
    }
    return std::string(peer_buffer);
}

bool LinkExistsInNamespace(const std::string& netns_path, const std::string& ifname) {
    auto entered = ScopedNetns::Enter(netns_path);
    if (!entered) {
        return false;
    }
    return LinkIndex(ifname).has_value();
}

bool StartListenerAndRoundTrip(const std::string& server_ns_path,
                               const std::string& client_ns_path,
                               const std::string& listen_address,
                               std::uint16_t port,
                               const std::string& payload) {
    std::promise<bool> server_ready;
    auto server_ready_future = server_ready.get_future();
    std::promise<bool> accepted_ok;
    auto accepted_ok_future = accepted_ok.get_future();

    std::thread server([&] {
        auto entered = ScopedNetns::Enter(server_ns_path);
        if (!entered) {
            accepted_ok.set_value(false);
            return;
        }
        ScopedFd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (!listener) {
            accepted_ok.set_value(false);
            return;
        }
        const int reuse = 1;
        if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
            accepted_ok.set_value(false);
            return;
        }
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, listen_address.c_str(), &server_addr.sin_addr) != 1 ||
            ::bind(listener.get(), reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) != 0 ||
            ::listen(listener.get(), 4) != 0) {
            accepted_ok.set_value(false);
            return;
        }
        server_ready.set_value(true);
        ScopedFd accepted = AcceptWithTimeout(listener.get(), std::chrono::duration_cast<std::chrono::milliseconds>(kIoTimeout));
        if (!accepted) {
            accepted_ok.set_value(false);
            return;
        }
        const auto request = ReadExact(accepted.get(), payload.size());
        if (!request.has_value() || *request != payload) {
            accepted_ok.set_value(false);
            return;
        }
        accepted_ok.set_value(SendAll(accepted.get(), *request));
    });

    if (server_ready_future.wait_for(kIoTimeout) != std::future_status::ready ||
        !server_ready_future.get()) {
        server.join();
        return false;
    }

    std::string reply;
    const bool client_ok = ConnectAndRoundTrip(client_ns_path, listen_address, port, payload, &reply);
    const bool server_ok =
        accepted_ok_future.wait_for(kIoTimeout) == std::future_status::ready && accepted_ok_future.get();
    server.join();
    return client_ok && server_ok && reply == payload;
}

std::atomic<unsigned int>& FixtureCounter() {
    static std::atomic<unsigned int> counter{0};
    return counter;
}

}  // namespace

NetnsFixture::NetnsFixture(std::string prefix,
                           std::filesystem::path state_root) noexcept
    : prefix_(std::move(prefix)),
      client_ns_(prefix_ + "-client"),
      proxy_ns_(prefix_ + "-proxy"),
      workload_ns_(prefix_ + "-workload"),
      state_root_(std::move(state_root)) {}

NetnsFixture::~NetnsFixture() {
    ResetNamespaces();
    for (const auto& link : root_links_) {
        RunCommand("/usr/bin/ip link delete " + link);
    }
    std::error_code ec;
    std::filesystem::remove_all(state_root_, ec);
}

NetnsFixture::NetnsFixture(NetnsFixture&& other) noexcept
    : prefix_(std::move(other.prefix_)),
      client_ns_(std::move(other.client_ns_)),
      proxy_ns_(std::move(other.proxy_ns_)),
      workload_ns_(std::move(other.workload_ns_)),
      state_root_(std::move(other.state_root_)),
      namespaces_created_(other.namespaces_created_) {
    other.namespaces_created_ = false;
}

NetnsFixture& NetnsFixture::operator=(NetnsFixture&& other) noexcept {
    if (this != &other) {
        ResetNamespaces();
        prefix_ = std::move(other.prefix_);
        client_ns_ = std::move(other.client_ns_);
        proxy_ns_ = std::move(other.proxy_ns_);
        workload_ns_ = std::move(other.workload_ns_);
        state_root_ = std::move(other.state_root_);
        namespaces_created_ = other.namespaces_created_;
        other.namespaces_created_ = false;
    }
    return *this;
}

bool NetnsFixture::HasRequiredPrivileges() {
    return HasCapNetAdmin() && ::access("/usr/bin/ip", X_OK) == 0;
}

std::optional<NetnsFixture> NetnsFixture::Create() {
    const auto suffix = std::to_string(::getpid()) + "-" +
                        std::to_string(FixtureCounter().fetch_add(1, std::memory_order_relaxed));
    auto fixture = NetnsFixture("inline-proxy-test-" + suffix,
                                std::filesystem::temp_directory_path() /
                                    ("inline-proxy-state-" + suffix));
    if (!fixture.CreateNamespaces()) {
        return std::nullopt;
    }
    return fixture;
}

bool NetnsFixture::CreateNamespaces() {
    std::error_code ec;
    std::filesystem::create_directories(state_root_, ec);
    namespaces_created_ = true;
    const bool ok = RunCommand("/usr/bin/ip netns add " + Quote(client_ns_)) &&
                    RunCommand("/usr/bin/ip netns add " + Quote(proxy_ns_)) &&
                    RunCommand("/usr/bin/ip netns add " + Quote(workload_ns_)) &&
                    RunCommand("/usr/bin/ip -n " + Quote(client_ns_) + " link set lo up") &&
                    RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " link set lo up") &&
                    RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " link set lo up");
    if (!ok) {
        ResetNamespaces();
    }
    return ok;
}

bool NetnsFixture::ResetNamespaces() {
    bool ok = true;
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(client_ns_));
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(proxy_ns_));
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(workload_ns_));
    namespaces_created_ = false;
    return ok;
}

bool NetnsFixture::RunCommand(const std::string& command) const {
    return std::system(command.c_str()) == 0;
}

bool NetnsFixture::RunTransparentRelayScenario() {
    if (!RunCommand("/usr/bin/ip link add cproxy0 type veth peer name ceth0") ||
        !RunCommand("/usr/bin/ip link set cproxy0 netns " + Quote(proxy_ns_)) ||
        !RunCommand("/usr/bin/ip link set ceth0 netns " + Quote(client_ns_)) ||
        !RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " addr add 10.20.0.1/24 dev cproxy0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " link set cproxy0 up") ||
        !RunCommand("/usr/bin/ip -n " + Quote(client_ns_) + " addr add 10.20.0.2/24 dev ceth0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(client_ns_) + " link set ceth0 up") ||
        !RunCommand("/usr/bin/ip link add lan0 type veth peer name app0") ||
        !RunCommand("/usr/bin/ip link set lan0 netns " + Quote(proxy_ns_)) ||
        !RunCommand("/usr/bin/ip link set app0 netns " + Quote(workload_ns_)) ||
        !RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " addr add 10.10.0.1/24 dev lan0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " link set lan0 up") ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " addr add 10.10.0.2/24 dev app0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " link set app0 up") ||
        !RunCommand("/usr/bin/ip -n " + Quote(client_ns_) +
                    " route add 10.10.0.2/32 via 10.20.0.1 dev ceth0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) +
                    " route add 10.20.0.0/24 via 10.10.0.1 dev app0")) {
        return false;
    }

    constexpr std::uint16_t kPort = 18080;
    const std::string payload = "relay-ping";

    std::promise<std::optional<std::string>> server_peer_promise;
    auto server_peer_future = server_peer_promise.get_future();
    std::thread server([&] {
        server_peer_promise.set_value(
            RunEchoServer(NamespacePath(workload_ns_), "10.10.0.2", kPort, payload));
    });

    {
        auto entered = ScopedNetns::Enter(NamespacePath(proxy_ns_));
        if (!entered) {
            server.join();
            return false;
        }

        auto listener = CreateTransparentListener("10.10.0.2", kPort);
        if (!listener) {
            server.join();
            return false;
        }

        std::promise<bool> client_done;
        auto client_done_future = client_done.get_future();
        std::string client_reply;
        std::thread client([&] {
            client_done.set_value(
                ConnectAndRoundTrip(NamespacePath(client_ns_), "10.10.0.2", kPort, payload, &client_reply));
        });

        ScopedFd accepted = AcceptWithTimeout(listener.fd(), std::chrono::duration_cast<std::chrono::milliseconds>(kIoTimeout));
        if (!accepted) {
            client.join();
            server.join();
            return false;
        }

        EventLoop loop;
        std::atomic<bool> session_closed{false};
        SessionEndpoints endpoints{
            .client = GetPeer(accepted.get()),
            .original_dst = GetSockName(accepted.get()),
        };
        auto session = CreateRelaySession(loop,
                                          std::move(accepted),
                                          endpoints,
                                          [&] {
                                              session_closed.store(true, std::memory_order_relaxed);
                                              loop.Stop();
                                          });
        if (!session) {
            client.join();
            server.join();
            return false;
        }

        std::thread runner([&] { loop.Run(); });
        const bool client_ok =
            client_done_future.wait_for(kIoTimeout) == std::future_status::ready && client_done_future.get();
        client.join();
        if (!session_closed.load(std::memory_order_relaxed)) {
            loop.Stop();
        }
        runner.join();
        server.join();

        bool server_ok = false;
        if (server_peer_future.wait_for(kIoTimeout) == std::future_status::ready) {
            const auto server_peer = server_peer_future.get();
            server_ok = server_peer.has_value() && *server_peer == "10.20.0.2";
        }
        return client_ok && server_ok && client_reply == payload;
    }
}

bool NetnsFixture::RunSpliceExecutorScenario() {
    const auto host_ifname = ShortIfName("host", prefix_);
    root_links_.push_back(host_ifname);
    if (!RunCommand("/usr/bin/ip link add " + host_ifname + " type veth peer name eth0") ||
        !RunCommand("/usr/bin/ip link set eth0 netns " + Quote(workload_ns_)) ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " link set eth0 up") ||
        !RunCommand("/usr/bin/ip link set " + host_ifname + " up")) {
        return false;
    }

    auto request = ParseCniRequest(
        R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]}})");
    if (!request.has_value()) {
        return false;
    }

    PodInfo workload_pod;
    workload_pod.name = "backend";
    workload_pod.namespace_name = "default";
    workload_pod.node_name = "worker-1";
    workload_pod.phase = "Running";
    workload_pod.running = true;
    workload_pod.annotations["inline-proxy.example.com/enabled"] = "true";

    PodInfo proxy_pod;
    proxy_pod.name = "inline-proxy-daemon";
    proxy_pod.namespace_name = "inline-proxy-system";
    proxy_pod.node_name = "worker-1";
    proxy_pod.phase = "Running";
    proxy_pod.running = true;
    proxy_pod.labels["app"] = "inline-proxy";

    SpliceExecutor executor({
        .state_root = state_root_,
        .workload_netns_path = NamespacePath(workload_ns_),
        .proxy_netns_path = NamespacePath(proxy_ns_),
    });
    const CniInvocation invocation{
        .request = *request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };
    const auto result = executor.HandleAdd(invocation, workload_pod, proxy_pod);
    if (!result.success || !result.plan.has_value()) {
        return false;
    }

    if (!LinkExistsInNamespace(NamespacePath(proxy_ns_), result.plan->wan_name) ||
        !LinkExistsInNamespace(NamespacePath(proxy_ns_), result.plan->lan_name) ||
        !LinkExistsInNamespace(NamespacePath(workload_ns_), "eth0")) {
        return false;
    }

    if (!RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " addr add 169.254.100.1/30 dev " +
                    result.plan->lan_name) ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " addr add 169.254.100.2/30 dev eth0") ||
        !RunCommand("/usr/bin/ip -n " + Quote(proxy_ns_) + " link set " + result.plan->lan_name + " up") ||
        !RunCommand("/usr/bin/ip -n " + Quote(workload_ns_) + " link set eth0 up")) {
        return false;
    }

    const bool round_trip =
        StartListenerAndRoundTrip(NamespacePath(proxy_ns_),
                                  NamespacePath(workload_ns_),
                                  "169.254.100.1",
                                  19090,
                                  "splice-ok");
    const auto del_result = executor.HandleDel(invocation);
    return round_trip && del_result.success;
}

}  // namespace inline_proxy
