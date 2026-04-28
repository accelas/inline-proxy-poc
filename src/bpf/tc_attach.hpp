#pragma once

#include <string>
#include <string_view>

#include "shared/scoped_fd.hpp"

namespace inline_proxy {

// CNI-side helper for attaching the inline-proxy TC ingress program to a
// named network interface. The program is expected to be pinned at
// `<pin_dir>/prog` by the CNI plugin's earlier proxy-DS-pod ADD; this
// class only opens the existing pin and runs the netlink TC dance.
//
// Caller threading: AttachToInterface uses the *current* thread's netns
// to resolve the interface and attach. Wan_<hash> lives in the proxy
// netns by the time the splice's ScopedNetns::Enter block reaches us.
class TcAttacher {
public:
    explicit TcAttacher(std::string pin_dir);

    // Opens the pinned prog, ensures clsact qdisc on `ifname`, attaches
    // a TC ingress filter referencing the prog. Idempotent — uses
    // NLM_F_REPLACE so a re-run on an already-attached interface is
    // safe.
    bool AttachToInterface(std::string_view ifname);

    const std::string& pin_dir() const noexcept { return pin_dir_; }

private:
    ScopedFd OpenPinnedProg() const;       // valid() false on failure
    bool EnsureClsact(unsigned int ifindex) const;
    bool AttachIngressFilter(unsigned int ifindex, int prog_fd) const;

    std::string pin_dir_;
};

}  // namespace inline_proxy
