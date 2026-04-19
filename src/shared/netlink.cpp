#include "shared/netlink.hpp"

#include "shared/scoped_fd.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
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

constexpr std::size_t kAlignTo = 4;

std::size_t Align(std::size_t size) {
    return (size + kAlignTo - 1) & ~(kAlignTo - 1);
}

bool AppendAttr(std::vector<char>& buffer, std::uint16_t type, const void* data, std::size_t size,
                bool nested = false) {
    const auto old_size = buffer.size();
    const auto total_size = NLA_HDRLEN + size;
    buffer.resize(old_size + Align(total_size));

    auto* attr = reinterpret_cast<nlattr*>(buffer.data() + old_size);
    attr->nla_type = nested ? static_cast<std::uint16_t>(type | NLA_F_NESTED) : type;
    attr->nla_len = static_cast<std::uint16_t>(total_size);
    std::memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, data, size);
    std::memset(reinterpret_cast<char*>(attr) + total_size, 0, Align(total_size) - total_size);
    return true;
}

bool AppendStringAttr(std::vector<char>& buffer, std::uint16_t type, const std::string& value,
                      bool nested = false) {
    return AppendAttr(buffer, type, value.c_str(), value.size() + 1, nested);
}

class NetlinkSocket {
public:
    static std::optional<NetlinkSocket> Open() {
        ScopedFd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
        if (!fd) {
            return std::nullopt;
        }

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = static_cast<unsigned int>(::getpid());
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            return std::nullopt;
        }

        return NetlinkSocket(std::move(fd));
    }

    bool Send(const std::vector<char>& request) const {
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        return ::sendto(fd_.get(), request.data(), request.size(), 0,
                        reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) >= 0;
    }

    bool ReceiveAck() const {
        std::array<char, 8192> buffer{};
        while (true) {
            const auto length = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
            if (length < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }

            auto remaining = static_cast<unsigned int>(length);
            for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer.data());
                 NLMSG_OK(header, remaining);
                 header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_type == NLMSG_ERROR) {
                    const auto* error = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(header));
                    return error->error == 0;
                }
                if (header->nlmsg_type == NLMSG_DONE) {
                    return true;
                }
            }
        }
    }

private:
    explicit NetlinkSocket(ScopedFd fd) : fd_(std::move(fd)) {}

    ScopedFd fd_;
};

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

    auto socket = NetlinkSocket::Open();
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

}  // namespace inline_proxy
