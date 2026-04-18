#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace inline_proxy {

struct K8sQuery {
    std::string namespace_name;
    std::string pod_name;
};

struct K8sClientOptions {
    std::string api_server_host;
    std::string api_server_port = "443";
    std::filesystem::path token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    std::filesystem::path ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    std::chrono::milliseconds timeout{5000};
};

struct PodInfo {
    std::string name;
    std::string namespace_name;
    std::string node_name;
    std::string phase;
    bool running = false;
    std::map<std::string, std::string> labels;
    std::map<std::string, std::string> annotations;
};

using K8sResponseFetcher = std::function<std::optional<std::string>(const K8sClientOptions&, const K8sQuery&)>;

void SetK8sResponseFetcherForTesting(K8sResponseFetcher fetcher);

std::string BuildK8sApiEndpoint(std::string_view host, std::string_view port);
std::string BuildK8sApiEndpoint(std::string_view host, std::uint16_t port);

std::optional<PodInfo> ParsePodInfo(std::string_view json);

PodInfo FetchPodInfo(const K8sQuery& query);
PodInfo FetchPodInfo(const K8sQuery& query, const K8sClientOptions& options);

}  // namespace inline_proxy
