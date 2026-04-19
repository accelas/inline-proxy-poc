#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <string_view>

#include "cni/k8s_client.hpp"
#include "cni/splice_executor.hpp"

namespace inline_proxy {

using NamespaceIpv4Matcher =
    std::function<bool(const std::filesystem::path&, std::string_view)>;

void SetNamespaceIpv4MatcherForTesting(NamespaceIpv4Matcher matcher);

std::optional<std::filesystem::path> ResolveWorkloadNetnsPath(
    const CniInvocation& invocation);

std::optional<std::filesystem::path> ResolveProxyNetnsPath(
    const PodInfo& proxy_pod,
    const std::filesystem::path& netns_root = "/var/run/netns");

}  // namespace inline_proxy
