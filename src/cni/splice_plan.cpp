#include "cni/splice_plan.hpp"

#include <stdexcept>
#include <utility>

namespace inline_proxy {
namespace {

std::string TruncateContainerId(std::string_view container_id) {
    const auto count = container_id.size() < 8 ? container_id.size() : 8;
    return std::string(container_id.substr(0, count));
}

std::string SanitizeContainerIdForPath(std::string_view container_id) {
    std::string sanitized;
    sanitized.reserve(container_id.size());
    for (const unsigned char ch : container_id) {
        const bool is_alnum = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
                              (ch >= 'a' && ch <= 'z');
        if (is_alnum || ch == '-' || ch == '_' || ch == '.') {
            sanitized.push_back(static_cast<char>(ch));
        } else {
            sanitized.push_back('_');
        }
    }
    if (sanitized.empty()) {
        sanitized = "unknown";
    }
    return "container-" + sanitized;
}

}  // namespace

SplicePlan BuildSplicePlan(std::string_view container_id,
                           std::string_view ifname,
                           std::filesystem::path state_root) {
    const std::string suffix = TruncateContainerId(container_id);
    SplicePlan plan;
    plan.container_id = std::string(container_id);
    plan.ifname = std::string(ifname);
    plan.wan_name = "wan_" + suffix;
    plan.lan_name = "lan_" + suffix;
    plan.state_path = std::move(state_root) / (SanitizeContainerIdForPath(container_id) + ".json");
    return plan;
}

bool IsProxyPod(const PodInfo& pod) {
    if (pod.namespace_name != "inline-proxy-system") {
        return false;
    }
    const auto label = pod.labels.find("app");
    if (label == pod.labels.end() || label->second != "inline-proxy") {
        return false;
    }
    return !pod.node_name.empty();
}

bool IsAnnotationEnabled(const PodInfo& pod, std::string_view annotation_key) {
    const auto it = pod.annotations.find(std::string(annotation_key));
    return it != pod.annotations.end() && it->second == "true";
}

bool MatchesNodeLocalProxy(const PodInfo& pod,
                           std::string_view node_name,
                           std::string_view namespace_name,
                           std::string_view label_key,
                           std::string_view label_value) {
    if (!pod.running) {
        return false;
    }
    if (pod.namespace_name != namespace_name) {
        return false;
    }
    const auto label = pod.labels.find(std::string(label_key));
    if (label == pod.labels.end() || label->second != label_value) {
        return false;
    }
    return pod.node_name == node_name;
}

std::string RenderPrevResultJson(const CniRequest& request) {
    if (request.prev_result_json.has_value()) {
        return *request.prev_result_json;
    }
    if (!request.prev_result.has_value()) {
        return "{}";
    }
    throw std::logic_error("prevResult JSON missing from parsed CNI request");
}

}  // namespace inline_proxy
