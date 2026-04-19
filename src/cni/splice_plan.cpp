#include "cni/splice_plan.hpp"

#include <sstream>
#include <utility>

namespace inline_proxy {
namespace {

std::string TruncateContainerId(std::string_view container_id) {
    const auto count = container_id.size() < 8 ? container_id.size() : 8;
    return std::string(container_id.substr(0, count));
}

void AppendEscaped(std::ostringstream& out, std::string_view value) {
    for (char ch : value) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch; break;
        }
    }
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
    plan.state_path = std::move(state_root) / (plan.container_id + ".json");
    return plan;
}

bool IsProxyPod(const PodInfo& pod) {
    return MatchesNodeLocalProxy(pod, pod.node_name);
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

std::string RenderPrevResultJson(const std::optional<PrevResult>& prev_result) {
    if (!prev_result.has_value()) {
        return "{}";
    }

    std::ostringstream out;
    out << "{\"interfaces\":[";
    for (std::size_t index = 0; index < prev_result->interfaces.size(); ++index) {
        if (index > 0) {
            out << ',';
        }
        const auto& iface = prev_result->interfaces[index];
        out << "{\"name\":\"";
        AppendEscaped(out, iface.name);
        out << "\"";
        if (iface.sandbox.has_value()) {
            out << ",\"sandbox\":\"";
            AppendEscaped(out, *iface.sandbox);
            out << "\"";
        }
        out << "}";
    }
    out << "]}";
    return out.str();
}

}  // namespace inline_proxy
