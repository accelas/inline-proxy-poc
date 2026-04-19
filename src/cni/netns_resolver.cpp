#include "cni/netns_resolver.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>

#include <mutex>

#include "shared/netns.hpp"

namespace inline_proxy {
namespace {

std::mutex& MatcherMutex() {
    static std::mutex mutex;
    return mutex;
}

NamespaceIpv4Matcher& MatcherRef() {
    static NamespaceIpv4Matcher matcher;
    return matcher;
}

bool NamespaceHasIpv4Address(const std::filesystem::path& netns_path,
                             std::string_view address) {
    auto entered = ScopedNetns::Enter(netns_path);
    if (!entered) {
        return false;
    }

    in_addr expected{};
    if (::inet_pton(AF_INET, std::string(address).c_str(), &expected) != 1) {
        return false;
    }

    ifaddrs* interfaces = nullptr;
    if (::getifaddrs(&interfaces) != 0) {
        return false;
    }

    bool found = false;
    for (ifaddrs* current = interfaces; current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr || current->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(*current->ifa_addr);
        if (ipv4.sin_addr.s_addr == expected.s_addr) {
            found = true;
            break;
        }
    }

    ::freeifaddrs(interfaces);
    return found;
}

bool MatchNamespaceIpv4(const std::filesystem::path& netns_path,
                        std::string_view address) {
    std::scoped_lock lock(MatcherMutex());
    if (auto& matcher = MatcherRef(); matcher) {
        return matcher(netns_path, address);
    }
    return NamespaceHasIpv4Address(netns_path, address);
}

}  // namespace

void SetNamespaceIpv4MatcherForTesting(NamespaceIpv4Matcher matcher) {
    std::scoped_lock lock(MatcherMutex());
    MatcherRef() = std::move(matcher);
}

std::optional<std::filesystem::path> ResolveWorkloadNetnsPath(
    const CniInvocation& invocation) {
    if (!invocation.request.prev_result.has_value()) {
        return std::nullopt;
    }

    const auto& interfaces = invocation.request.prev_result->interfaces;
    for (const auto& iface : interfaces) {
        if (iface.name == invocation.ifname && iface.sandbox.has_value() &&
            !iface.sandbox->empty()) {
            return std::filesystem::path(*iface.sandbox);
        }
    }

    for (const auto& iface : interfaces) {
        if (iface.sandbox.has_value() && !iface.sandbox->empty()) {
            return std::filesystem::path(*iface.sandbox);
        }
    }

    return std::nullopt;
}

std::optional<std::filesystem::path> ResolveProxyNetnsPath(
    const PodInfo& proxy_pod,
    const std::filesystem::path& netns_root) {
    if (proxy_pod.pod_ip.empty() || !std::filesystem::exists(netns_root) ||
        !std::filesystem::is_directory(netns_root)) {
        return std::nullopt;
    }

    for (const auto& entry : std::filesystem::directory_iterator(netns_root)) {
        const auto path = entry.path();
        if (MatchNamespaceIpv4(path, proxy_pod.pod_ip)) {
            return path;
        }
    }

    return std::nullopt;
}

}  // namespace inline_proxy
