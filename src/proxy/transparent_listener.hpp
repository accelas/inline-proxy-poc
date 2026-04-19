#pragma once

#include <cstdint>
#include <string>

#include "shared/scoped_fd.hpp"

namespace inline_proxy {

class TransparentListener {
public:
    TransparentListener() noexcept = default;
    explicit TransparentListener(ScopedFd fd) noexcept;

    bool ok() const noexcept;
    int fd() const noexcept;
    explicit operator bool() const noexcept;

private:
    ScopedFd fd_;
};

TransparentListener CreateTransparentListener(const std::string& address, std::uint16_t port);

}  // namespace inline_proxy
