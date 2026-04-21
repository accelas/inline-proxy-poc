#include "proxy/local_source.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <ifaddrs.h>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "shared/netlink.hpp"

namespace inline_proxy {
namespace {

AcquireLocalSourceHook& AcquireLocalSourceHookRef() {
    static AcquireLocalSourceHook hook = nullptr;
    return hook;
}

ReleaseLocalSourceHook& ReleaseLocalSourceHookRef() {
    static ReleaseLocalSourceHook hook = nullptr;
    return hook;
}

class LocalSourceManager {
public:
    bool Acquire(const sockaddr_storage& addr) {
        if (addr.ss_family != AF_INET) {
            return true;
        }

        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
        const std::uint32_t key = ipv4.sin_addr.s_addr;

        std::lock_guard<std::mutex> lock(mu_);
        auto& entry = refs_[key];
        if (entry.refs == 0) {
            // Do not add a /32 copy of the client IP if it is already
            // locally assigned in this netns, or if it is a next-hop
            // gateway referenced in any route (meaning the IP lives in
            // another netns — for example the cni0 bridge IP in k3s —
            // and adding a /32 here would break ARP resolution for every
            // pod in the netns).
            if (IsLocallyAssigned(ipv4.sin_addr) ||
                IsGatewayAddress(ipv4.sin_addr)) {
                entry.interfaces.clear();
                ++entry.refs;
                return true;
            }
            entry.interfaces = CandidateInterfaces();
            if (entry.interfaces.empty()) {
                entry.interfaces = {"lo"};
            }
            for (const auto& ifname : entry.interfaces) {
                if (AddLocalAddress(ifname, ipv4.sin_addr, 32)) {
                    continue;
                }
                for (const auto& added : entry.interfaces) {
                    if (added == ifname) {
                        break;
                    }
                    (void)RemoveLocalAddress(added, ipv4.sin_addr, 32);
                }
                entry.interfaces.clear();
                refs_.erase(key);
                return false;
            }
        }
        ++entry.refs;
        return true;
    }

    void Release(const sockaddr_storage& addr) {
        if (addr.ss_family != AF_INET) {
            return;
        }

        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
        const std::uint32_t key = ipv4.sin_addr.s_addr;

        std::lock_guard<std::mutex> lock(mu_);
        const auto it = refs_.find(key);
        if (it == refs_.end()) {
            return;
        }

        if (it->second.refs > 1) {
            --it->second.refs;
            return;
        }

        // interfaces is empty iff Acquire short-circuited because the IP was
        // already locally assigned; nothing to remove in that case.
        for (const auto& ifname : it->second.interfaces) {
            (void)RemoveLocalAddress(ifname, ipv4.sin_addr, 32);
        }
        refs_.erase(it);
    }

private:
    struct RefEntry {
        std::size_t refs = 0;
        std::vector<std::string> interfaces;
    };

    static bool IsLocallyAssigned(const in_addr& address) {
        ifaddrs* interfaces = nullptr;
        if (::getifaddrs(&interfaces) != 0) {
            return false;
        }
        bool found = false;
        for (ifaddrs* c = interfaces; c != nullptr; c = c->ifa_next) {
            if (c->ifa_addr == nullptr || c->ifa_addr->sa_family != AF_INET) {
                continue;
            }
            const auto& v4 = reinterpret_cast<const sockaddr_in&>(*c->ifa_addr);
            if (v4.sin_addr.s_addr == address.s_addr) {
                found = true;
                break;
            }
        }
        ::freeifaddrs(interfaces);
        return found;
    }

    // True if the given IP is a next-hop gateway referenced in any IPv4
    // route in this netns. Reads /proc/net/route, which is netns-local.
    // Used to avoid AddLocalAddress for IPs that are actually OFF-netns
    // (e.g. the cni0 bridge gateway IP 10.42.0.1 in k3s) — assigning a /32
    // of such an IP to wan_ causes the kernel to suppress ARP replies for
    // every address whose subnet overlaps the conflicting /32, breaking
    // host↔pod connectivity throughout the netns.
    static bool IsGatewayAddress(const in_addr& address) {
        std::ifstream route("/proc/self/net/route");
        if (!route) return false;
        std::string line;
        std::getline(route, line);  // header
        while (std::getline(route, line)) {
            std::istringstream is(line);
            std::string iface, dst_hex, gw_hex;
            if (!(is >> iface >> dst_hex >> gw_hex)) continue;
            if (gw_hex.size() != 8) continue;
            std::uint32_t gw_le = 0;
            try {
                gw_le = static_cast<std::uint32_t>(std::stoul(gw_hex, nullptr, 16));
            } catch (...) {
                continue;
            }
            if (gw_le == address.s_addr) {
                return true;
            }
        }
        return false;
    }

    static std::vector<std::string> CandidateInterfaces() {
        std::vector<std::string> interfaces;
        ifaddrs* all = nullptr;
        if (::getifaddrs(&all) != 0) {
            return interfaces;
        }
        std::set<std::string> seen;
        for (ifaddrs* c = all; c != nullptr; c = c->ifa_next) {
            if (c->ifa_name == nullptr) continue;
            const std::string name(c->ifa_name);
            if (name.rfind("wan_", 0) == 0 && seen.insert(name).second) {
                interfaces.push_back(name);
            }
        }
        ::freeifaddrs(all);
        return interfaces;
    }

    std::mutex mu_;
    std::unordered_map<std::uint32_t, RefEntry> refs_;
};

LocalSourceManager& LocalSourceManagerRef() {
    static LocalSourceManager manager;
    return manager;
}

bool SkipLocalSourceEnabled() {
    const char* value = std::getenv("INLINE_PROXY_SKIP_LOCAL_SOURCE");
    return value != nullptr && std::string_view(value) == "1";
}

}  // namespace

bool AcquireLocalSourceAddress(const sockaddr_storage& addr) {
    if (auto hook = AcquireLocalSourceHookRef()) {
        return hook(addr);
    }
    if (SkipLocalSourceEnabled()) {
        return true;
    }
    return LocalSourceManagerRef().Acquire(addr);
}

void ReleaseLocalSourceAddress(const sockaddr_storage& addr) {
    if (auto hook = ReleaseLocalSourceHookRef()) {
        hook(addr);
        return;
    }
    if (SkipLocalSourceEnabled()) {
        return;
    }
    LocalSourceManagerRef().Release(addr);
}

void SetAcquireLocalSourceHookForTesting(AcquireLocalSourceHook hook) {
    AcquireLocalSourceHookRef() = hook;
}

void SetReleaseLocalSourceHookForTesting(ReleaseLocalSourceHook hook) {
    ReleaseLocalSourceHookRef() = hook;
}

}  // namespace inline_proxy
