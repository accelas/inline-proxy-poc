#include "shared/netns.hpp"

#include <sys/socket.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include <utility>

namespace inline_proxy {
namespace {

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

bool SendFd(int socket_fd, int fd_to_send) {
    char byte = 'n';
    iovec iov{
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd_to_send;
    msg.msg_controllen = cmsg->cmsg_len;

    return ::sendmsg(socket_fd, &msg, 0) >= 0;
}

ScopedFd ReceiveFd(int socket_fd) {
    char byte = 0;
    iovec iov{
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    if (::recvmsg(socket_fd, &msg, 0) < 0) {
        return {};
    }

    for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            return ScopedFd(*reinterpret_cast<int*>(CMSG_DATA(cmsg)));
        }
    }

    return {};
}

}  // namespace

NetnsHandle::NetnsHandle(ScopedFd fd, std::string name) noexcept
    : fd_(std::move(fd)), name_(std::move(name)) {}

NetnsHandle::NetnsHandle(NetnsHandle&& other) noexcept
    : fd_(std::move(other.fd_)), name_(std::move(other.name_)) {}

NetnsHandle& NetnsHandle::operator=(NetnsHandle&& other) noexcept {
    if (this != &other) {
        fd_ = std::move(other.fd_);
        name_ = std::move(other.name_);
    }
    return *this;
}

std::optional<NetnsHandle> NetnsHandle::Create(std::string name) {
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        return std::nullopt;
    }

    ScopedFd parent_socket(sockets[0]);
    ScopedFd child_socket(sockets[1]);

    const pid_t child = ::fork();
    if (child < 0) {
        return std::nullopt;
    }
    if (child == 0) {
        parent_socket.reset();
        if (::unshare(CLONE_NEWNET) != 0) {
            _exit(1);
        }
        ScopedFd ns_fd = OpenNetnsFd("/proc/self/ns/net");
        if (!ns_fd || !SendFd(child_socket.get(), ns_fd.get())) {
            _exit(1);
        }
        _exit(0);
    }

    child_socket.reset();
    ScopedFd ns_fd = ReceiveFd(parent_socket.get());
    int status = 0;
    if (::waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        !ns_fd) {
        return std::nullopt;
    }

    return NetnsHandle(std::move(ns_fd), std::move(name));
}

int NetnsHandle::fd() const noexcept {
    return fd_.get();
}

bool NetnsHandle::valid() const noexcept {
    return static_cast<bool>(fd_);
}

NetnsHandle::operator bool() const noexcept {
    return valid();
}

const std::string& NetnsHandle::name() const noexcept {
    return name_;
}

void NetnsHandle::reset() noexcept {
    fd_.reset();
    name_.clear();
}

ScopedNetns::ScopedNetns(ScopedFd previous_netns) noexcept
    : previous_netns_(std::move(previous_netns)) {}

ScopedNetns::~ScopedNetns() {
    if (previous_netns_) {
        ::setns(previous_netns_.get(), CLONE_NEWNET);
    }
}

ScopedNetns::ScopedNetns(ScopedNetns&& other) noexcept
    : previous_netns_(std::move(other.previous_netns_)) {}

ScopedNetns& ScopedNetns::operator=(ScopedNetns&& other) noexcept {
    if (this != &other) {
        previous_netns_ = std::move(other.previous_netns_);
    }
    return *this;
}

std::optional<ScopedNetns> ScopedNetns::Enter(const std::filesystem::path& netns_path) {
    auto previous = OpenNetnsFd("/proc/self/ns/net");
    if (!previous) {
        return std::nullopt;
    }

    auto target = OpenNetnsFd(netns_path);
    if (!target) {
        return std::nullopt;
    }

    if (::setns(target.get(), CLONE_NEWNET) != 0) {
        return std::nullopt;
    }

    return ScopedNetns(std::move(previous));
}

std::optional<ScopedNetns> ScopedNetns::Enter(int netns_fd) {
    auto previous = OpenNetnsFd("/proc/self/ns/net");
    if (!previous) {
        return std::nullopt;
    }

    if (::setns(netns_fd, CLONE_NEWNET) != 0) {
        return std::nullopt;
    }

    return ScopedNetns(std::move(previous));
}

bool ScopedNetns::valid() const noexcept {
    return static_cast<bool>(previous_netns_);
}

ScopedNetns::operator bool() const noexcept {
    return valid();
}

}  // namespace inline_proxy
