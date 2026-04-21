#include "proxy/local_source.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <mutex>
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

    static std::vector<std::string> CandidateInterfaces() {
        std::vector<std::string> interfaces;
        for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net")) {
            const auto name = entry.path().filename().string();
            if (name.rfind("wan_", 0) == 0) {
                interfaces.push_back(name);
            }
        }
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
