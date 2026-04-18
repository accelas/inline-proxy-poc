#include "shared/netns.hpp"

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <utility>

namespace inline_proxy {
namespace {

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

}  // namespace

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

bool ScopedNetns::valid() const noexcept {
    return static_cast<bool>(previous_netns_);
}

ScopedNetns::operator bool() const noexcept {
    return valid();
}

}  // namespace inline_proxy
