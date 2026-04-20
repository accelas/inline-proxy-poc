#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>

namespace inline_proxy {

std::optional<unsigned int> LinkIndex(const std::string& ifname) noexcept;
bool SetLinkUp(const std::string& ifname, bool up = true);
bool SetLinkMtu(const std::string& ifname, unsigned int mtu);
bool RenameLink(const std::string& ifname, const std::string& new_name);
bool DeleteLink(const std::string& ifname);
bool MoveLinkToNetns(const std::string& ifname, int netns_fd);
bool CreateVethPair(const std::string& left_ifname, const std::string& right_ifname);
bool AddLocalAddress(const std::string& ifname, const in_addr& address, std::uint8_t prefix_len = 32);
bool RemoveLocalAddress(const std::string& ifname,
                        const in_addr& address,
                        std::uint8_t prefix_len = 32);

// ---------------------------------------------------------------------------
// High-level route / rule / address helpers (rtnetlink). Replacements for
// the previous `RunIp({...})` shell-outs. Each function operates in the
// calling thread's current netns.
// ---------------------------------------------------------------------------

// Route configuration. `cidr` accepts "default", "0.0.0.0/0",
// "10.42.0.0/24", "10.42.0.1/32", etc. `table` defaults to the main table.
// For the transparent-proxy "local 0/0 dev lo" pattern set type = RTN_LOCAL
// and scope = RT_SCOPE_HOST.
struct RouteConfig {
    std::string cidr;
    std::string oif;                    // output ifname
    std::optional<std::string> via;     // gateway IP (dotted-decimal)
    std::uint32_t table = 254u;         // RT_TABLE_MAIN
    std::uint8_t type = 1u;             // RTN_UNICAST
    std::uint8_t scope = 0u;            // RT_SCOPE_UNIVERSE
};

bool AddRoute(const RouteConfig& cfg, bool replace = true);
bool DeleteRoute(const RouteConfig& cfg);

// Delete every route in `table`. Implemented as a dump + per-entry delete
// (single-shot like `ip route flush table N`).
bool FlushRouteTable(std::uint32_t table);

// Policy-routing rule (IPv4). At least one of `src_cidr` or `fwmark`
// should be set — an empty rule would match everything.
struct RuleConfig {
    std::optional<std::string> src_cidr;
    std::optional<std::uint32_t> fwmark;
    std::uint32_t table = 254u;         // RT_TABLE_MAIN
};

bool AddRule(const RuleConfig& cfg);
bool DeleteRule(const RuleConfig& cfg);

// Generic "ip addr add <cidr> dev <ifname>" equivalent. Accepts any
// prefix length (not just /32 like AddLocalAddress).
bool AddInterfaceAddress(const std::string& ifname, const std::string& cidr);
bool RemoveInterfaceAddress(const std::string& ifname, const std::string& cidr);
bool FlushInterfaceAddresses(const std::string& ifname);

}  // namespace inline_proxy
