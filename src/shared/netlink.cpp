#include "shared/netlink.hpp"

#include "shared/netlink_builder.hpp"
#include "shared/scoped_fd.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ifaddrs.h>
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

}  // namespace inline_proxy
