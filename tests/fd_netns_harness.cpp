#include "tests/fd_netns_harness.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <thread>
#include <vector>

#include "proxy/config.hpp"
#include "proxy/relay_session.hpp"
#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/netlink.hpp"
#include "shared/sockaddr.hpp"

namespace inline_proxy {
namespace {

constexpr std::chrono::seconds kIoTimeout(5);
constexpr unsigned int kCapNetAdminBit = 12;
constexpr unsigned int kCapNetBindServiceBit = 10;
constexpr std::uint16_t kDemoPort = 80;
constexpr std::uint16_t kListenerPort = 15001;
constexpr char kClientIp[] = "10.10.1.2";
constexpr char kClientGateway[] = "10.10.1.1";
constexpr char kServerIp[] = "10.10.2.2";
constexpr char kServerGateway[] = "10.10.2.1";

bool HasCapabilityBit(unsigned int bit) {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("CapEff:\t", 0) != 0) {
            continue;
        }
        const auto hex_caps = line.substr(sizeof("CapEff:\t") - 1);
        try {
            const auto capabilities = std::stoull(hex_caps, nullptr, 16);
            return (capabilities & (1ULL << bit)) != 0;
        } catch (...) {
            return false;
        }
    }
    return false;
}

bool RunIpInNamespace(int netns_fd, const std::vector<std::string>& args) {
    const pid_t child = ::fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        if (::setns(netns_fd, CLONE_NEWNET) != 0) {
            _exit(127);
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(const_cast<char*>("/sbin/ip"));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        ::execv("/sbin/ip", argv.data());
        _exit(127);
    }

    int status = 0;
    return ::waitpid(child, &status, 0) >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool SetIpv4Forwarding(const NetnsHandle& netns, bool enabled) {
    auto entered = ScopedNetns::Enter(netns.fd());
    if (!entered) {
        return false;
    }
    std::ofstream stream("/proc/sys/net/ipv4/ip_forward");
    if (!stream) {
        return false;
    }
    stream << (enabled ? "1\n" : "0\n");
    return static_cast<bool>(stream);
}

bool SendAll(int fd, const std::string& payload) {
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const ssize_t written =
            ::send(fd, payload.data() + offset, payload.size() - offset, MSG_NOSIGNAL);
        if (written <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

std::optional<std::string> ReadExact(int fd, std::size_t expected) {
    std::string output(expected, '\0');
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

class NamespaceSocketServer {
public:
    static void RunEchoServer(const NetnsHandle& netns,
                              TransparentFlowObservation* observation,
                              std::promise<bool>* ready,
                              std::promise<bool>* done,
                              std::string expected_payload) {
        auto entered = ScopedNetns::Enter(netns.fd());
        if (!entered) {
            ready->set_value(false);
            done->set_value(false);
            return;
        }

        ScopedFd listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (!listener) {
            ready->set_value(false);
            done->set_value(false);
            return;
        }

        const int reuse = 1;
        ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        auto addr = MakeSockaddr4(kServerIp, kDemoPort);
        if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in)) != 0 ||
            ::listen(listener.get(), 8) != 0) {
            ready->set_value(false);
            done->set_value(false);
            return;
        }

        ready->set_value(true);
        ScopedFd accepted(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
        if (!accepted) {
            done->set_value(false);
            return;
        }

        observation->server_peer = FormatSockaddr(GetPeer(accepted.get()));
        auto payload = ReadExact(accepted.get(), expected_payload.size());
        if (!payload.has_value() || *payload != expected_payload || !SendAll(accepted.get(), *payload)) {
            done->set_value(false);
            return;
        }
        done->set_value(true);
    }
};

bool RunClientRoundTrip(const NetnsHandle& netns,
                        std::string_view payload,
                        std::string* reply) {
    auto entered = ScopedNetns::Enter(netns.fd());
    if (!entered) {
        return false;
    }

    ScopedFd fd(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!fd) {
        return false;
    }

    auto addr = MakeSockaddr4(kServerIp, kDemoPort);
    if (::connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in)) != 0) {
        return false;
    }
    if (!SendAll(fd.get(), std::string(payload))) {
        return false;
    }
    ::shutdown(fd.get(), SHUT_WR);
    auto result = ReadExact(fd.get(), payload.size());
    if (!result.has_value()) {
        return false;
    }
    if (reply) {
        *reply = *result;
    }
    return true;
}

}  // namespace

FdNetnsHarness::FdNetnsHarness(NetnsHandle client,
                               NetnsHandle proxy,
                               NetnsHandle server) noexcept
    : client_(std::move(client)), proxy_(std::move(proxy)), server_(std::move(server)) {}

FdNetnsHarness::~FdNetnsHarness() = default;

FdNetnsHarness::FdNetnsHarness(FdNetnsHarness&& other) noexcept
    : client_(std::move(other.client_)),
      proxy_(std::move(other.proxy_)),
      server_(std::move(other.server_)),
      wan_ifname_(std::move(other.wan_ifname_)),
      lan_ifname_(std::move(other.lan_ifname_)),
      observation_(std::move(other.observation_)) {}

FdNetnsHarness& FdNetnsHarness::operator=(FdNetnsHarness&& other) noexcept {
    if (this != &other) {
        client_ = std::move(other.client_);
        proxy_ = std::move(other.proxy_);
        server_ = std::move(other.server_);
        wan_ifname_ = std::move(other.wan_ifname_);
        lan_ifname_ = std::move(other.lan_ifname_);
        observation_ = std::move(other.observation_);
    }
    return *this;
}

bool FdNetnsHarness::HasRequiredPrivileges() {
    return HasCapabilityBit(kCapNetAdminBit) && HasCapabilityBit(kCapNetBindServiceBit) &&
           ::access("/sbin/ip", X_OK) == 0;
}

std::optional<FdNetnsHarness> FdNetnsHarness::Create() {
    auto client = NetnsHandle::Create("clt");
    auto proxy = NetnsHandle::Create("proxy");
    auto server = NetnsHandle::Create("svr");
    if (!client || !proxy || !server) {
        return std::nullopt;
    }

    auto harness = std::optional<FdNetnsHarness>(
        FdNetnsHarness(std::move(*client), std::move(*proxy), std::move(*server)));
    if (!harness->SetupTopology()) {
        return std::nullopt;
    }
    return harness;
}

bool FdNetnsHarness::SetupTopology() {
    if (!CreateVethPair("clt_host0", wan_ifname_)) {
        return false;
    }
    if (!MoveLinkToNetns("clt_host0", client_.fd()) || !MoveLinkToNetns(wan_ifname_, proxy_.fd())) {
        return false;
    }
    if (!CreateVethPair(lan_ifname_, "svr_host0")) {
        return false;
    }
    if (!MoveLinkToNetns(lan_ifname_, proxy_.fd()) || !MoveLinkToNetns("svr_host0", server_.fd())) {
        return false;
    }

    {
        auto client_ns = ScopedNetns::Enter(client_.fd());
        if (!client_ns || !RenameLink("clt_host0", "eth0") || !SetLinkUp("lo") || !SetLinkUp("eth0")) {
            return false;
        }
    }
    {
        auto proxy_ns = ScopedNetns::Enter(proxy_.fd());
        if (!proxy_ns || !SetLinkUp("lo") || !SetLinkUp(wan_ifname_) || !SetLinkUp(lan_ifname_)) {
            return false;
        }
    }
    {
        auto server_ns = ScopedNetns::Enter(server_.fd());
        if (!server_ns || !RenameLink("svr_host0", "eth0") || !SetLinkUp("lo") || !SetLinkUp("eth0")) {
            return false;
        }
    }

    if (!RunIpInNamespace(client_.fd(), {"addr", "add", std::string(kClientIp) + "/24", "dev", "eth0"}) ||
        !RunIpInNamespace(client_.fd(), {"route", "add", "default", "via", kClientGateway, "dev", "eth0"})) {
        return false;
    }
    if (!RunIpInNamespace(proxy_.fd(), {"addr", "add", std::string(kClientGateway) + "/24", "dev", wan_ifname_}) ||
        !RunIpInNamespace(proxy_.fd(), {"addr", "add", std::string(kServerGateway) + "/24", "dev", lan_ifname_})) {
        return false;
    }
    if (!RunIpInNamespace(server_.fd(), {"addr", "add", std::string(kServerIp) + "/24", "dev", "eth0"}) ||
        !RunIpInNamespace(server_.fd(), {"route", "add", "default", "via", kServerGateway, "dev", "eth0"})) {
        return false;
    }

    return SetIpv4Forwarding(proxy_, true);
}

bool FdNetnsHarness::RunInterceptEchoScenario() {
    constexpr char kPayload[] = "fd-netns-echo";
    std::promise<bool> server_ready;
    std::promise<bool> server_done;
    auto server_ready_future = server_ready.get_future();
    auto server_done_future = server_done.get_future();
    std::thread server_thread(NamespaceSocketServer::RunEchoServer,
                              std::cref(server_),
                              &observation_,
                              &server_ready,
                              &server_done,
                              std::string(kPayload));
    if (server_ready_future.wait_for(kIoTimeout) != std::future_status::ready ||
        !server_ready_future.get()) {
        server_thread.join();
        return false;
    }

    std::promise<bool> proxy_ready;
    auto proxy_ready_future = proxy_ready.get_future();
    std::promise<bool> proxy_done;
    auto proxy_done_future = proxy_done.get_future();

    std::thread proxy_thread([&] {
        auto entered = ScopedNetns::Enter(proxy_.fd());
        if (!entered || !InstallTransparentRoutingRule()) {
            proxy_ready.set_value(false);
            proxy_done.set_value(false);
            return;
        }

        InterfaceRegistry registry;
        auto listener = CreateTransparentListener("0.0.0.0", kListenerPort);
        if (!listener || !registry.ConfigureIngressListener(listener.fd(), kDemoPort) ||
            !registry.RecordInterface(wan_ifname_)) {
            proxy_ready.set_value(false);
            proxy_done.set_value(false);
            return;
        }

        EventLoop loop;
        std::vector<std::shared_ptr<RelaySession>> sessions;
        proxy_ready.set_value(true);
        auto handle = loop.Register(
            listener.fd(),
            true,
            false,
            [&] {
                ScopedFd accepted(::accept4(listener.fd(), nullptr, nullptr, SOCK_CLOEXEC));
                if (!accepted || !SetNonBlocking(accepted.get())) {
                    return;
                }
                SessionEndpoints endpoints{
                    .client = GetPeer(accepted.get()),
                    .original_dst = GetSockName(accepted.get()),
                };
                observation_.proxy_client = FormatSockaddr(endpoints.client);
                observation_.proxy_original_dst = FormatSockaddr(endpoints.original_dst);
                observation_.accepted_connections.fetch_add(1, std::memory_order_relaxed);
                auto session = CreateRelaySession(loop, std::move(accepted), endpoints, [&] { loop.Stop(); });
                if (!session) {
                    loop.Stop();
                    return;
                }
                sessions.push_back(std::move(session));
            },
            {},
            [&](int) { loop.Stop(); });
        (void)handle;
        loop.Run();
        proxy_done.set_value(true);
    });

    if (proxy_ready_future.wait_for(kIoTimeout) != std::future_status::ready ||
        !proxy_ready_future.get()) {
        proxy_thread.join();
        server_thread.join();
        return false;
    }

    std::string reply;
    const bool client_ok = RunClientRoundTrip(client_, kPayload, &reply);
    const bool server_ok =
        server_done_future.wait_for(kIoTimeout) == std::future_status::ready && server_done_future.get();
    const bool proxy_ok =
        proxy_done_future.wait_for(kIoTimeout) == std::future_status::ready && proxy_done_future.get();

    proxy_thread.join();
    server_thread.join();
    return client_ok && server_ok && proxy_ok && reply == kPayload;
}

const TransparentFlowObservation& FdNetnsHarness::observation() const noexcept {
    return observation_;
}

}  // namespace inline_proxy
