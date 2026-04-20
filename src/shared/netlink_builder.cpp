#include "shared/netlink_builder.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/rtnetlink.h>

namespace inline_proxy {
namespace netlink {

bool AppendAttr(std::vector<char>& buffer,
                std::uint16_t type,
                const void* data,
                std::size_t size,
                bool nested) {
    const auto old_size = buffer.size();
    const auto total_size = NLA_HDRLEN + size;
    buffer.resize(old_size + Align(total_size));

    auto* attr = reinterpret_cast<nlattr*>(buffer.data() + old_size);
    attr->nla_type = nested ? static_cast<std::uint16_t>(type | NLA_F_NESTED) : type;
    attr->nla_len = static_cast<std::uint16_t>(total_size);
    std::memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, data, size);
    std::memset(reinterpret_cast<char*>(attr) + total_size, 0,
                Align(total_size) - total_size);
    return true;
}

bool AppendStringAttr(std::vector<char>& buffer,
                      std::uint16_t type,
                      const std::string& value,
                      bool nested) {
    return AppendAttr(buffer, type, value.c_str(), value.size() + 1, nested);
}

std::optional<Socket> Socket::Open() {
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

    return Socket(std::move(fd));
}

bool Socket::Send(const std::vector<char>& request) const {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    return ::sendto(fd_.get(), request.data(), request.size(), 0,
                    reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) >= 0;
}

bool Socket::ReceiveAck() const {
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

std::optional<std::vector<std::vector<char>>> Socket::ReceiveDump() const {
    std::vector<std::vector<char>> responses;
    std::array<char, 32 * 1024> buffer{};
    while (true) {
        const auto length = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::nullopt;
        }

        auto remaining = static_cast<unsigned int>(length);
        for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer.data());
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_ERROR) {
                const auto* error = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(header));
                if (error->error != 0) {
                    return std::nullopt;
                }
                // Shouldn't see a clean ACK in a dump, but tolerate it.
                continue;
            }
            if (header->nlmsg_type == NLMSG_DONE) {
                return responses;
            }
            // Copy the full nlmsghdr + payload so callers can parse
            // attributes after the Socket goes out of scope.
            const auto* raw = reinterpret_cast<const char*>(header);
            responses.emplace_back(raw, raw + header->nlmsg_len);
        }
    }
}

}  // namespace netlink
}  // namespace inline_proxy
