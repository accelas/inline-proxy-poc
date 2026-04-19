#include "cni/cni_args.hpp"

#include <cstddef>
#include <string>

namespace inline_proxy {

std::optional<CniPodIdentity> ParseCniArgs(std::string_view cni_args) {
    CniPodIdentity identity;
    bool saw_namespace = false;
    bool saw_pod_name = false;

    std::size_t start = 0;
    while (start <= cni_args.size()) {
        const auto end = cni_args.find(';', start);
        const auto token = cni_args.substr(start, end == std::string_view::npos ? std::string_view::npos
                                                                                : end - start);
        if (!token.empty()) {
            const auto equals = token.find('=');
            if (equals != std::string_view::npos && equals > 0) {
                const auto key = token.substr(0, equals);
                const auto value = token.substr(equals + 1);
                if (key == "K8S_POD_NAMESPACE") {
                    identity.namespace_name = std::string(value);
                    saw_namespace = true;
                } else if (key == "K8S_POD_NAME") {
                    identity.pod_name = std::string(value);
                    saw_pod_name = true;
                }
            }
        }

        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }

    if (!saw_namespace || !saw_pod_name || identity.namespace_name.empty() || identity.pod_name.empty()) {
        return std::nullopt;
    }

    return identity;
}

}  // namespace inline_proxy
