#pragma once

// Internal netlink primitives used by every netlink-building .cpp in the
// codebase. Not part of the public //src/shared:shared API surface in
// `netlink.hpp` — those declare higher-level operations (LinkIndex,
// CreateVethPair, ...). This header exposes the low-level helpers
// (attribute serialisation, the RAII socket wrapper) so that
// src/bpf/loader.cpp can share them instead of maintaining a parallel
// copy.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "shared/scoped_fd.hpp"

namespace inline_proxy {
namespace netlink {

constexpr std::size_t kAlignTo = 4;

constexpr std::size_t Align(std::size_t size) noexcept {
    return (size + kAlignTo - 1) & ~(kAlignTo - 1);
}

bool AppendAttr(std::vector<char>& buffer,
                std::uint16_t type,
                const void* data,
                std::size_t size,
                bool nested = false);

bool AppendStringAttr(std::vector<char>& buffer,
                      std::uint16_t type,
                      const std::string& value,
                      bool nested = false);

class Socket {
public:
    static std::optional<Socket> Open();

    bool Send(const std::vector<char>& request) const;

    // Receive a single ACK/error response; returns true iff NLMSG_ERROR
    // carried error == 0.
    bool ReceiveAck() const;

    // Receive a multi-part dump response terminated by NLMSG_DONE.
    // Returns each response payload as a separate heap-allocated copy
    // (NLMSG_DONE itself is not included). On transport failure the
    // returned optional is empty.
    std::optional<std::vector<std::vector<char>>> ReceiveDump() const;

private:
    explicit Socket(ScopedFd fd) : fd_(std::move(fd)) {}
    ScopedFd fd_;
};

}  // namespace netlink
}  // namespace inline_proxy
