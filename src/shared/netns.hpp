#pragma once

#include "shared/scoped_fd.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace inline_proxy {

class NetnsHandle {
public:
    NetnsHandle() noexcept = default;
    explicit NetnsHandle(ScopedFd fd, std::string name = {}) noexcept;

    NetnsHandle(NetnsHandle&& other) noexcept;
    NetnsHandle& operator=(NetnsHandle&& other) noexcept;

    NetnsHandle(const NetnsHandle&) = delete;
    NetnsHandle& operator=(const NetnsHandle&) = delete;

    static std::optional<NetnsHandle> Create(std::string name = {});

    int fd() const noexcept;
    bool valid() const noexcept;
    explicit operator bool() const noexcept;
    const std::string& name() const noexcept;
    void reset() noexcept;

private:
    ScopedFd fd_;
    std::string name_;
};

class ScopedNetns {
public:
    ScopedNetns() noexcept = default;
    ~ScopedNetns();

    ScopedNetns(ScopedNetns&& other) noexcept;
    ScopedNetns& operator=(ScopedNetns&& other) noexcept;

    ScopedNetns(const ScopedNetns&) = delete;
    ScopedNetns& operator=(const ScopedNetns&) = delete;

    static std::optional<ScopedNetns> Enter(const std::filesystem::path& netns_path);
    static std::optional<ScopedNetns> Enter(int netns_fd);

    bool valid() const noexcept;
    explicit operator bool() const noexcept;

private:
    explicit ScopedNetns(ScopedFd previous_netns) noexcept;

    ScopedFd previous_netns_;
};

}  // namespace inline_proxy
