#pragma once

#include "shared/scoped_fd.hpp"

#include <filesystem>
#include <optional>

namespace inline_proxy {

class ScopedNetns {
public:
    ScopedNetns() noexcept = default;
    ~ScopedNetns();

    ScopedNetns(ScopedNetns&& other) noexcept;
    ScopedNetns& operator=(ScopedNetns&& other) noexcept;

    ScopedNetns(const ScopedNetns&) = delete;
    ScopedNetns& operator=(const ScopedNetns&) = delete;

    static std::optional<ScopedNetns> Enter(const std::filesystem::path& netns_path);

    bool valid() const noexcept;
    explicit operator bool() const noexcept;

private:
    explicit ScopedNetns(ScopedFd previous_netns) noexcept;

    ScopedFd previous_netns_;
};

}  // namespace inline_proxy
