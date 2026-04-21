#include "shared/netlink.hpp"

#include "shared/netlink_builder.hpp"
#include "shared/scoped_fd.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <ifaddrs.h>
#include <linux/fib_rules.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace inline_proxy {
namespace {

using netlink::AppendAttr;
using netlink::AppendStringAttr;

std::vector<char> MakeLinkRequest(std::uint16_t type, std::uint16_t flags, unsigned int index = 0) {
    std::vector<char> request(NLMSG_LENGTH(sizeof(ifinfomsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* link = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(header));
    std::memset(link, 0, sizeof(*link));
    link->ifi_family = AF_UNSPEC;
    link->ifi_index = static_cast<int>(index);
    link->ifi_change = 0xffffffffu;
    return request;
}

bool SendLinkRequest(std::vector<char> request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());

    auto socket = netlink::Socket::Open();
    if (!socket) {
        return false;
    }
    if (!socket->Send(request)) {
        return false;
    }
    return socket->ReceiveAck();
}

std::vector<char> MakeRawIfInfo() {
    return std::vector<char>(sizeof(ifinfomsg), '\0');
}

std::vector<char> MakeAddressRequest(std::uint16_t type,
                                     std::uint16_t flags,
                                     unsigned int index,
                                     std::uint8_t prefix_len) {
    std::vector<char> request(NLMSG_LENGTH(sizeof(ifaddrmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* addr = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(header));
    std::memset(addr, 0, sizeof(*addr));
    addr->ifa_family = AF_INET;
    addr->ifa_prefixlen = prefix_len;
    addr->ifa_scope = RT_SCOPE_HOST;
    addr->ifa_index = index;
    return request;
}

bool SendAddressRequest(std::vector<char> request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());

    auto socket = netlink::Socket::Open();
    if (!socket) {
        return false;
    }
    if (!socket->Send(request)) {
        return false;
    }
    return socket->ReceiveAck();
}

bool InterfaceHasAddress(const std::string& ifname, const in_addr& address) {
    ifaddrs* interfaces = nullptr;
    if (::getifaddrs(&interfaces) != 0) {
        return false;
    }

    bool found = false;
    for (ifaddrs* current = interfaces; current != nullptr; current = current->ifa_next) {
        if (current->ifa_name == nullptr || current->ifa_addr == nullptr ||
            current->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (ifname != current->ifa_name) {
            continue;
        }
        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(*current->ifa_addr);
        if (ipv4.sin_addr.s_addr == address.s_addr) {
            found = true;
            break;
        }
    }

    ::freeifaddrs(interfaces);
    return found;
}

}  // namespace

std::optional<unsigned int> LinkIndex(const std::string& ifname) noexcept {
    const auto index = ::if_nametoindex(ifname.c_str());
    if (index == 0) {
        return std::nullopt;
    }
    return index;
}

bool SetLinkUp(const std::string& ifname, bool up) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }

    auto request = MakeLinkRequest(RTM_NEWLINK, 0, *index);
    auto* link = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    link->ifi_flags = up ? IFF_UP : 0;
    link->ifi_change = IFF_UP;
    return SendLinkRequest(std::move(request));
}

bool SetLinkMtu(const std::string& ifname, unsigned int mtu) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }
    auto request = MakeLinkRequest(RTM_NEWLINK, 0, *index);
    const std::uint32_t mtu_value = mtu;
    AppendAttr(request, IFLA_MTU, &mtu_value, sizeof(mtu_value));
    return SendLinkRequest(std::move(request));
}

bool RenameLink(const std::string& ifname, const std::string& new_name) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }

    auto request = MakeLinkRequest(RTM_NEWLINK, 0, *index);
    AppendStringAttr(request, IFLA_IFNAME, new_name);
    return SendLinkRequest(std::move(request));
}

bool DeleteLink(const std::string& ifname) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }

    auto request = MakeLinkRequest(RTM_DELLINK, 0, *index);
    return SendLinkRequest(std::move(request));
}

bool MoveLinkToNetns(const std::string& ifname, int netns_fd) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }

    auto request = MakeLinkRequest(RTM_NEWLINK, 0, *index);
    AppendAttr(request, IFLA_NET_NS_FD, &netns_fd, sizeof(netns_fd));
    return SendLinkRequest(std::move(request));
}

bool CreateVethPair(const std::string& left_ifname, const std::string& right_ifname) {
    auto request = MakeLinkRequest(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);

    auto peer = MakeRawIfInfo();
    AppendStringAttr(peer, IFLA_IFNAME, right_ifname);

    std::vector<char> veth_data;
    AppendAttr(veth_data, VETH_INFO_PEER, peer.data(), peer.size(), true);

    std::vector<char> linkinfo;
    AppendStringAttr(linkinfo, IFLA_INFO_KIND, "veth");
    AppendAttr(linkinfo, IFLA_INFO_DATA, veth_data.data(), veth_data.size(), true);

    AppendStringAttr(request, IFLA_IFNAME, left_ifname);
    AppendAttr(request, IFLA_LINKINFO, linkinfo.data(), linkinfo.size(), true);
    return SendLinkRequest(std::move(request));
}

bool AddLocalAddress(const std::string& ifname, const in_addr& address, std::uint8_t prefix_len) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }
    if (InterfaceHasAddress(ifname, address)) {
        return true;
    }

    auto request = MakeAddressRequest(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, *index, prefix_len);
    AppendAttr(request, IFA_LOCAL, &address, sizeof(address));
    AppendAttr(request, IFA_ADDRESS, &address, sizeof(address));
    return SendAddressRequest(std::move(request));
}

bool RemoveLocalAddress(const std::string& ifname, const in_addr& address, std::uint8_t prefix_len) {
    const auto index = LinkIndex(ifname);
    if (!index) {
        return false;
    }
    if (!InterfaceHasAddress(ifname, address)) {
        return true;
    }

    auto request = MakeAddressRequest(RTM_DELADDR, 0, *index, prefix_len);
    AppendAttr(request, IFA_LOCAL, &address, sizeof(address));
    AppendAttr(request, IFA_ADDRESS, &address, sizeof(address));
    return SendAddressRequest(std::move(request));
}

// ---------------------------------------------------------------------------
// Route / Rule / Address helpers. Replace RunIp({...}) shell-outs.
// ---------------------------------------------------------------------------

namespace {

struct ParsedCidr {
    in_addr address{};
    std::uint8_t prefix_len = 0;
};

std::optional<ParsedCidr> ParseCidr(const std::string& cidr) {
    // Accept "default", "0.0.0.0/0", "10.42.0.0/24", "10.42.0.1" (= /32).
    ParsedCidr out;
    if (cidr == "default") {
        out.address.s_addr = 0;
        out.prefix_len = 0;
        return out;
    }
    const auto slash = cidr.find('/');
    const std::string addr_part = cidr.substr(0, slash);
    if (::inet_pton(AF_INET, addr_part.c_str(), &out.address) != 1) {
        return std::nullopt;
    }
    if (slash == std::string::npos) {
        out.prefix_len = 32;
    } else {
        try {
            const auto prefix = std::stoul(cidr.substr(slash + 1));
            if (prefix > 32u) return std::nullopt;
            out.prefix_len = static_cast<std::uint8_t>(prefix);
        } catch (...) {
            return std::nullopt;
        }
    }
    return out;
}

std::vector<char> MakeRouteRequest(std::uint16_t type,
                                   std::uint16_t flags,
                                   const ParsedCidr& dst,
                                   unsigned int oif_index,
                                   const std::optional<in_addr>& gw,
                                   std::uint32_t table,
                                   std::uint8_t route_type,
                                   std::uint8_t scope) {
    std::vector<char> request(NLMSG_LENGTH(sizeof(rtmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* rt = reinterpret_cast<rtmsg*>(NLMSG_DATA(header));
    std::memset(rt, 0, sizeof(*rt));
    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = dst.prefix_len;
    rt->rtm_table = (table <= 255u) ? static_cast<std::uint8_t>(table) : RT_TABLE_UNSPEC;
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_scope = scope;
    rt->rtm_type = route_type;

    if (dst.prefix_len > 0) {
        AppendAttr(request, RTA_DST, &dst.address, sizeof(dst.address));
    }
    if (oif_index != 0) {
        const std::uint32_t oif = oif_index;
        AppendAttr(request, RTA_OIF, &oif, sizeof(oif));
    }
    if (gw.has_value()) {
        AppendAttr(request, RTA_GATEWAY, &gw->s_addr, sizeof(gw->s_addr));
    }
    // Always pass table as a 32-bit attribute so values > 255 work.
    AppendAttr(request, RTA_TABLE, &table, sizeof(table));
    return request;
}

bool SendSimpleRequest(std::vector<char> request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    auto socket = netlink::Socket::Open();
    if (!socket) return false;
    if (!socket->Send(request)) return false;
    return socket->ReceiveAck();
}

std::vector<char> MakeRuleRequest(std::uint16_t type,
                                  std::uint16_t flags,
                                  const std::optional<ParsedCidr>& src,
                                  const std::optional<std::uint32_t>& fwmark,
                                  std::uint32_t table) {
    std::vector<char> request(NLMSG_LENGTH(sizeof(rtmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* rt = reinterpret_cast<rtmsg*>(NLMSG_DATA(header));
    std::memset(rt, 0, sizeof(*rt));
    rt->rtm_family = AF_INET;
    rt->rtm_src_len = src.has_value() ? src->prefix_len : 0;
    rt->rtm_table = (table <= 255u) ? static_cast<std::uint8_t>(table) : RT_TABLE_UNSPEC;
    rt->rtm_type = FR_ACT_TO_TBL;
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;

    if (src.has_value() && src->prefix_len > 0) {
        AppendAttr(request, FRA_SRC, &src->address, sizeof(src->address));
    }
    if (fwmark.has_value()) {
        const std::uint32_t mark = *fwmark;
        AppendAttr(request, FRA_FWMARK, &mark, sizeof(mark));
    }
    AppendAttr(request, FRA_TABLE, &table, sizeof(table));
    return request;
}

std::vector<char> MakeAddressCidrRequest(std::uint16_t type,
                                         std::uint16_t flags,
                                         unsigned int index,
                                         std::uint8_t prefix_len,
                                         std::uint8_t scope) {
    std::vector<char> request(NLMSG_LENGTH(sizeof(ifaddrmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* addr = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(header));
    std::memset(addr, 0, sizeof(*addr));
    addr->ifa_family = AF_INET;
    addr->ifa_prefixlen = prefix_len;
    addr->ifa_scope = scope;
    addr->ifa_index = index;
    return request;
}

std::uint8_t ScopeForPrefix(std::uint8_t prefix_len) {
    // /32 entries are "host-scope" local addresses; anything else is a
    // normal on-link route and should be RT_SCOPE_UNIVERSE (== 0).
    return prefix_len == 32u ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
}

}  // namespace

bool AddRoute(const RouteConfig& cfg, bool replace) {
    const auto dst = ParseCidr(cfg.cidr);
    if (!dst) {
        std::cerr << "netlink AddRoute: bad cidr=" << cfg.cidr << '\n';
        return false;
    }
    const auto index = LinkIndex(cfg.oif);
    if (!index) {
        std::cerr << "netlink AddRoute: oif not found oif=" << cfg.oif << '\n';
        return false;
    }
    std::optional<in_addr> via;
    if (cfg.via.has_value()) {
        in_addr parsed{};
        if (::inet_pton(AF_INET, cfg.via->c_str(), &parsed) != 1) {
            std::cerr << "netlink AddRoute: bad via=" << *cfg.via << '\n';
            return false;
        }
        via = parsed;
    }
    const std::uint16_t flags =
        static_cast<std::uint16_t>(NLM_F_CREATE | (replace ? NLM_F_REPLACE : NLM_F_EXCL));
    // Match `ip route add`: on-link device routes (oif set, no gateway,
    // unicast) default to RT_SCOPE_LINK, not RT_SCOPE_UNIVERSE. Needed so a
    // subsequent `via <gw>` route can treat <gw> as on-link via that oif.
    std::uint8_t effective_scope = cfg.scope;
    if (effective_scope == RT_SCOPE_UNIVERSE && !via.has_value() && cfg.type == RTN_UNICAST) {
        effective_scope = RT_SCOPE_LINK;
    }
    auto request = MakeRouteRequest(RTM_NEWROUTE, flags, *dst, *index, via,
                                    cfg.table, cfg.type, effective_scope);
    if (!SendSimpleRequest(std::move(request))) {
        std::cerr << "netlink AddRoute: send failed cidr=" << cfg.cidr
                  << " oif=" << cfg.oif
                  << " via=" << (cfg.via.value_or("<none>"))
                  << " table=" << cfg.table << '\n';
        return false;
    }
    return true;
}

bool DeleteRoute(const RouteConfig& cfg) {
    const auto dst = ParseCidr(cfg.cidr);
    if (!dst) return false;
    const auto index = LinkIndex(cfg.oif);
    if (!index) return false;
    std::optional<in_addr> via;
    if (cfg.via.has_value()) {
        in_addr parsed{};
        if (::inet_pton(AF_INET, cfg.via->c_str(), &parsed) != 1) return false;
        via = parsed;
    }
    auto request = MakeRouteRequest(RTM_DELROUTE, 0, *dst, *index, via,
                                    cfg.table, cfg.type, cfg.scope);
    return SendSimpleRequest(std::move(request));
}

bool FlushRouteTable(std::uint32_t table) {
    // Dump routes, filter by table, issue DELETE for each.
    std::vector<char> dump_request(NLMSG_LENGTH(sizeof(rtmsg)));
    {
        auto* header = reinterpret_cast<nlmsghdr*>(dump_request.data());
        header->nlmsg_len = static_cast<std::uint32_t>(dump_request.size());
        header->nlmsg_type = RTM_GETROUTE;
        header->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        header->nlmsg_seq = 1;
        auto* rt = reinterpret_cast<rtmsg*>(NLMSG_DATA(header));
        std::memset(rt, 0, sizeof(*rt));
        rt->rtm_family = AF_INET;
    }

    auto socket = netlink::Socket::Open();
    if (!socket) return false;
    if (!socket->Send(dump_request)) return false;
    auto dump = socket->ReceiveDump();
    if (!dump.has_value()) return false;

    bool all_ok = true;
    for (const auto& msg : *dump) {
        const auto* header = reinterpret_cast<const nlmsghdr*>(msg.data());
        if (header->nlmsg_type != RTM_NEWROUTE) continue;
        const auto* rt = reinterpret_cast<const rtmsg*>(NLMSG_DATA(header));
        // Walk attributes, extract RTA_TABLE (may be 32-bit) and RTA_OIF / RTA_DST.
        std::uint32_t msg_table = rt->rtm_table;
        std::optional<in_addr> dst_addr;
        std::uint32_t oif = 0;
        std::optional<in_addr> gw;
        const auto* attrs = reinterpret_cast<const char*>(rt) + sizeof(*rt);
        unsigned int attr_len = header->nlmsg_len - NLMSG_LENGTH(sizeof(*rt));
        for (const rtattr* a = reinterpret_cast<const rtattr*>(attrs);
             RTA_OK(a, attr_len);
             a = RTA_NEXT(a, attr_len)) {
            const auto* payload = reinterpret_cast<const char*>(RTA_DATA(a));
            switch (a->rta_type) {
                case RTA_TABLE:
                    if (RTA_PAYLOAD(a) == sizeof(std::uint32_t)) {
                        std::memcpy(&msg_table, payload, sizeof(msg_table));
                    }
                    break;
                case RTA_DST:
                    if (RTA_PAYLOAD(a) == sizeof(in_addr)) {
                        in_addr addr{};
                        std::memcpy(&addr, payload, sizeof(addr));
                        dst_addr = addr;
                    }
                    break;
                case RTA_OIF:
                    if (RTA_PAYLOAD(a) == sizeof(std::uint32_t)) {
                        std::memcpy(&oif, payload, sizeof(oif));
                    }
                    break;
                case RTA_GATEWAY:
                    if (RTA_PAYLOAD(a) == sizeof(in_addr)) {
                        in_addr addr{};
                        std::memcpy(&addr, payload, sizeof(addr));
                        gw = addr;
                    }
                    break;
                default:
                    break;
            }
        }
        if (msg_table != table) continue;

        // Synthesize a DELETE for the matching route.
        ParsedCidr cidr{};
        if (dst_addr.has_value()) {
            cidr.address = *dst_addr;
        } else {
            cidr.address.s_addr = 0;
        }
        cidr.prefix_len = rt->rtm_dst_len;
        auto del = MakeRouteRequest(RTM_DELROUTE, 0, cidr, oif, gw, table,
                                    rt->rtm_type, rt->rtm_scope);
        if (!SendSimpleRequest(std::move(del))) all_ok = false;
    }
    return all_ok;
}

bool AddRule(const RuleConfig& cfg) {
    std::optional<ParsedCidr> src;
    if (cfg.src_cidr.has_value()) {
        src = ParseCidr(*cfg.src_cidr);
        if (!src) {
            std::cerr << "netlink AddRule: bad src_cidr=" << *cfg.src_cidr << '\n';
            return false;
        }
    }
    auto request = MakeRuleRequest(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL,
                                   src, cfg.fwmark, cfg.table);
    if (!SendSimpleRequest(std::move(request))) {
        std::cerr << "netlink AddRule: send failed src=" << cfg.src_cidr.value_or("<none>")
                  << " table=" << cfg.table << '\n';
        return false;
    }
    return true;
}

bool DeleteRule(const RuleConfig& cfg) {
    std::optional<ParsedCidr> src;
    if (cfg.src_cidr.has_value()) {
        src = ParseCidr(*cfg.src_cidr);
        if (!src) return false;
    }
    auto request = MakeRuleRequest(RTM_DELRULE, 0, src, cfg.fwmark, cfg.table);
    return SendSimpleRequest(std::move(request));
}

bool AddInterfaceAddress(const std::string& ifname, const std::string& cidr) {
    const auto parsed = ParseCidr(cidr);
    if (!parsed) {
        std::cerr << "netlink AddInterfaceAddress: bad cidr=" << cidr << '\n';
        return false;
    }
    const auto index = LinkIndex(ifname);
    if (!index) {
        std::cerr << "netlink AddInterfaceAddress: ifname not found ifname=" << ifname << '\n';
        return false;
    }
    auto request = MakeAddressCidrRequest(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL,
                                          *index, parsed->prefix_len,
                                          ScopeForPrefix(parsed->prefix_len));
    AppendAttr(request, IFA_LOCAL, &parsed->address, sizeof(parsed->address));
    AppendAttr(request, IFA_ADDRESS, &parsed->address, sizeof(parsed->address));
    if (!SendSimpleRequest(std::move(request))) {
        std::cerr << "netlink AddInterfaceAddress: send failed ifname=" << ifname
                  << " cidr=" << cidr << '\n';
        return false;
    }
    return true;
}

bool RemoveInterfaceAddress(const std::string& ifname, const std::string& cidr) {
    const auto parsed = ParseCidr(cidr);
    if (!parsed) return false;
    const auto index = LinkIndex(ifname);
    if (!index) return false;
    auto request = MakeAddressCidrRequest(RTM_DELADDR, 0, *index,
                                          parsed->prefix_len,
                                          ScopeForPrefix(parsed->prefix_len));
    AppendAttr(request, IFA_LOCAL, &parsed->address, sizeof(parsed->address));
    AppendAttr(request, IFA_ADDRESS, &parsed->address, sizeof(parsed->address));
    return SendSimpleRequest(std::move(request));
}

bool FlushInterfaceAddresses(const std::string& ifname) {
    const auto index = LinkIndex(ifname);
    if (!index) return false;

    // Dump addresses, filter by ifindex, issue DELADDR for each IPv4 entry.
    std::vector<char> dump(NLMSG_LENGTH(sizeof(ifaddrmsg)));
    {
        auto* header = reinterpret_cast<nlmsghdr*>(dump.data());
        header->nlmsg_len = static_cast<std::uint32_t>(dump.size());
        header->nlmsg_type = RTM_GETADDR;
        header->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        header->nlmsg_seq = 1;
        auto* addr = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(header));
        std::memset(addr, 0, sizeof(*addr));
        addr->ifa_family = AF_INET;
    }

    auto socket = netlink::Socket::Open();
    if (!socket) return false;
    if (!socket->Send(dump)) return false;
    auto responses = socket->ReceiveDump();
    if (!responses.has_value()) return false;

    bool all_ok = true;
    for (const auto& msg : *responses) {
        const auto* header = reinterpret_cast<const nlmsghdr*>(msg.data());
        if (header->nlmsg_type != RTM_NEWADDR) continue;
        const auto* addr = reinterpret_cast<const ifaddrmsg*>(NLMSG_DATA(header));
        if (addr->ifa_index != *index) continue;
        if (addr->ifa_family != AF_INET) continue;

        // Find the IFA_LOCAL (or IFA_ADDRESS) attr.
        const auto* attrs = reinterpret_cast<const char*>(addr) + sizeof(*addr);
        unsigned int attr_len = header->nlmsg_len - NLMSG_LENGTH(sizeof(*addr));
        std::optional<in_addr> local;
        for (const rtattr* a = reinterpret_cast<const rtattr*>(attrs);
             RTA_OK(a, attr_len);
             a = RTA_NEXT(a, attr_len)) {
            if ((a->rta_type == IFA_LOCAL || a->rta_type == IFA_ADDRESS) &&
                RTA_PAYLOAD(a) == sizeof(in_addr)) {
                in_addr v{};
                std::memcpy(&v, RTA_DATA(a), sizeof(v));
                local = v;
                if (a->rta_type == IFA_LOCAL) break;  // prefer IFA_LOCAL
            }
        }
        if (!local.has_value()) continue;

        auto del = MakeAddressCidrRequest(RTM_DELADDR, 0, *index, addr->ifa_prefixlen,
                                          addr->ifa_scope);
        AppendAttr(del, IFA_LOCAL, &local->s_addr, sizeof(local->s_addr));
        AppendAttr(del, IFA_ADDRESS, &local->s_addr, sizeof(local->s_addr));
        if (!SendSimpleRequest(std::move(del))) all_ok = false;
    }
    return all_ok;
}

}  // namespace inline_proxy
