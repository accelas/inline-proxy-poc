#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "cni/cni_types.hpp"
#include "cni/k8s_client.hpp"

namespace inline_proxy {

struct SplicePlan {
    std::string container_id;
    std::string ifname;
    std::string wan_name;
    std::string lan_name;
    std::filesystem::path state_path;
};

SplicePlan BuildSplicePlan(std::string_view container_id,
                           std::string_view ifname,
                           std::filesystem::path state_root = "/var/run/inline-proxy-cni");

bool IsProxyPod(const PodInfo& pod);
bool IsAnnotationEnabled(const PodInfo& pod, std::string_view annotation_key = "inline-proxy.example.com/enabled");
bool MatchesNodeLocalProxy(const PodInfo& pod,
                           std::string_view node_name,
                           std::string_view namespace_name = "inline-proxy-system",
                           std::string_view label_key = "app",
                           std::string_view label_value = "inline-proxy");

std::string RenderPrevResultJson(const std::optional<PrevResult>& prev_result);

}  // namespace inline_proxy
