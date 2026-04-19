#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace inline_proxy {

struct CniPodIdentity {
    std::string namespace_name;
    std::string pod_name;
};

std::optional<CniPodIdentity> ParseCniArgs(std::string_view cni_args);

}  // namespace inline_proxy
