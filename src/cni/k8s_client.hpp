#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace inline_proxy {

struct K8sQuery {
    std::string namespace_name;
    std::string pod_name;
};

struct K8sPodListQuery {
    std::string namespace_name;
    std::string label_selector;
};

struct K8sClientOptions {
    std::string api_server_host;
    std::string api_server_port = "443";
    std::filesystem::path token_path;
    std::filesystem::path ca_path;
    std::filesystem::path client_cert_path;
    std::filesystem::path client_key_path;
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
using K8sPodListResponseFetcher = std::function<std::optional<std::string>(const K8sClientOptions&, const K8sPodListQuery&)>;

void SetK8sResponseFetcherForTesting(K8sResponseFetcher fetcher);
void SetK8sPodListResponseFetcherForTesting(K8sPodListResponseFetcher fetcher);

std::string BuildK8sApiEndpoint(std::string_view host, std::string_view port);
std::string BuildK8sApiEndpoint(std::string_view host, std::uint16_t port);

std::optional<PodInfo> ParsePodInfo(std::string_view json);
std::vector<PodInfo> ParsePodList(std::string_view json);

PodInfo FetchPodInfo(const K8sQuery& query);
PodInfo FetchPodInfo(const K8sQuery& query, const K8sClientOptions& options);

std::vector<PodInfo> FetchPodList(const K8sPodListQuery& query);
std::vector<PodInfo> FetchPodList(const K8sPodListQuery& query, const K8sClientOptions& options);

std::optional<PodInfo> FindNodeLocalProxyPod(std::string_view node_name);
std::optional<PodInfo> FindNodeLocalProxyPod(std::string_view node_name, const K8sClientOptions& options);

}  // namespace inline_proxy
