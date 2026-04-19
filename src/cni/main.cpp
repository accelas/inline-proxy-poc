#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include "cni/k8s_client.hpp"
#include "cni/splice_executor.hpp"
#include "cni/yajl_parser.hpp"

namespace {

std::optional<std::string> GetEnv(std::string_view name) {
    const std::string key(name);
    if (const char* value = std::getenv(key.c_str())) {
        return std::string(value);
    }
    return std::nullopt;
}

std::string ReadStdin() {
    std::ostringstream buffer;
    buffer << std::cin.rdbuf();
    return buffer.str();
}

}  // namespace

int main() {
    try {
        const auto command = GetEnv("CNI_COMMAND");
        if (!command.has_value() || command->empty()) {
            std::cerr << "missing CNI_COMMAND\n";
            return 1;
        }

        const auto container_id = GetEnv("CNI_CONTAINERID");
        if (!container_id.has_value() || container_id->empty()) {
            std::cerr << "missing CNI_CONTAINERID\n";
            return 1;
        }

        const auto ifname = GetEnv("CNI_IFNAME").value_or("eth0");

        inline_proxy::SpliceExecutor executor;
        inline_proxy::CniInvocation invocation{
            .request = {},
            .container_id = *container_id,
            .ifname = ifname,
        };

        if (*command == "DEL") {
            const auto result = executor.HandleDel(invocation);
            if (!result.success) {
                std::cerr << result.stderr_text << "\n";
                return 1;
            }
            return 0;
        }

        if (*command != "ADD") {
            std::cerr << "unsupported CNI command: " << *command << "\n";
            return 1;
        }

        const auto pod_namespace = GetEnv("K8S_POD_NAMESPACE");
        const auto pod_name = GetEnv("K8S_POD_NAME");
        if (!pod_namespace.has_value() || pod_namespace->empty() ||
            !pod_name.has_value() || pod_name->empty()) {
            std::cerr << "missing K8S_POD_NAMESPACE or K8S_POD_NAME\n";
            return 1;
        }

        const auto request = inline_proxy::ParseCniRequest(ReadStdin());
        if (!request.has_value()) {
            std::cerr << "failed to parse CNI request\n";
            return 1;
        }

        const inline_proxy::K8sQuery workload_query{.namespace_name = *pod_namespace, .pod_name = *pod_name};
        const auto workload_pod = inline_proxy::FetchPodInfo(workload_query);

        invocation.request = *request;

        const auto proxy_pod = inline_proxy::FindNodeLocalProxyPod(workload_pod.node_name);
        const auto result = executor.HandleAdd(invocation, workload_pod, proxy_pod);
        if (!result.success) {
            std::cerr << result.stderr_text << "\n";
            return 1;
        }

        std::cout << result.stdout_json;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
