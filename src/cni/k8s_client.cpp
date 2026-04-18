#include "cni/k8s_client.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace inline_proxy {
namespace {

using Json = nlohmann::json;

std::mutex& FetcherMutex() {
    static std::mutex mutex;
    return mutex;
}

K8sResponseFetcher& Fetcher() {
    static K8sResponseFetcher fetcher;
    return fetcher;
}


std::string Trim(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    std::size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t' || value[start] == '\n' || value[start] == '\r')) {
        ++start;
    }
    return value.substr(start);
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream stream(path);
    if (!stream) {
        throw std::runtime_error("failed to open file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

K8sClientOptions LoadDefaultOptions() {
    K8sClientOptions options;
    if (const char* host = std::getenv("KUBERNETES_SERVICE_HOST")) {
        options.api_server_host = host;
    }
    if (const char* port = std::getenv("KUBERNETES_SERVICE_PORT")) {
        options.api_server_port = port;
    }
    if (const char* token_path = std::getenv("INLINE_PROXY_K8S_TOKEN_PATH")) {
        options.token_path = token_path;
    }
    if (const char* ca_path = std::getenv("INLINE_PROXY_K8S_CA_PATH")) {
        options.ca_path = ca_path;
    }
    return options;
}

std::string BuildPodPath(const K8sQuery& query) {
    if (query.namespace_name.empty() || query.pod_name.empty()) {
        throw std::invalid_argument("namespace and pod name must be non-empty");
    }
    return "/api/v1/namespaces/" + query.namespace_name + "/pods/" + query.pod_name;
}

std::string BuildHttpRequest(const K8sClientOptions& options, const K8sQuery& query, const std::string& token) {
    std::ostringstream request;
    request << "GET " << BuildPodPath(query) << " HTTP/1.1\r\n";
    request << "Host: " << options.api_server_host << "\r\n";
    request << "Authorization: Bearer " << token << "\r\n";
    request << "Accept: application/json\r\n";
    request << "Connection: close\r\n\r\n";
    return request.str();
}

int ConnectTcp(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* results = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &results);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") + ::gai_strerror(rc));
    }

    int fd = -1;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
        fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(results);
    if (fd < 0) {
        throw std::runtime_error("failed to connect to Kubernetes API server");
    }
    return fd;
}

std::string PerformHttpsGet(const K8sClientOptions& options, const K8sQuery& query, const std::string& token) {
    const int fd = ConnectTcp(options.api_server_host, options.api_server_port);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ::close(fd);
        throw std::runtime_error("failed to create SSL context");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(ctx, options.ca_path.string().c_str(), nullptr) != 1) {
        SSL_CTX_free(ctx);
        ::close(fd);
        throw std::runtime_error("failed to load Kubernetes CA bundle");
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        ::close(fd);
        throw std::runtime_error("failed to create SSL object");
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, options.api_server_host.c_str());
    if (SSL_set1_host(ssl, options.api_server_host.c_str()) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
        throw std::runtime_error("failed to configure TLS hostname verification");
    }

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
        throw std::runtime_error("failed to negotiate TLS with Kubernetes API server");
    }

    const std::string request = BuildHttpRequest(options, query, token);
    const char* data = request.data();
    std::size_t remaining = request.size();
    while (remaining > 0) {
        const int written = SSL_write(ssl, data, static_cast<int>(remaining));
        if (written <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            ::close(fd);
            throw std::runtime_error("failed to send Kubernetes API request");
        }
        data += written;
        remaining -= static_cast<std::size_t>(written);
    }

    std::string response;
    char buffer[4096];
    for (;;) {
        const int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            response.append(buffer, buffer + bytes_read);
            continue;
        }
        const int error = SSL_get_error(ssl, bytes_read);
        if (error == SSL_ERROR_ZERO_RETURN) {
            break;
        }
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
        throw std::runtime_error("failed to read Kubernetes API response");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(fd);
    return response;
}

std::string ExtractBody(const std::string& response) {
    const std::string delimiter = "\r\n\r\n";
    const auto pos = response.find(delimiter);
    if (pos == std::string::npos) {
        throw std::runtime_error("malformed HTTP response from Kubernetes API server");
    }

    const std::string status_line = response.substr(0, response.find("\r\n"));
    if (status_line.size() < 12 || status_line.rfind("HTTP/", 0) != 0) {
        throw std::runtime_error("malformed HTTP status line from Kubernetes API server");
    }

    const auto first_space = status_line.find(' ');
    const auto second_space = status_line.find(' ', first_space + 1);
    if (first_space == std::string::npos || second_space == std::string::npos) {
        throw std::runtime_error("malformed HTTP status line from Kubernetes API server");
    }
    const int status = std::stoi(status_line.substr(first_space + 1, second_space - first_space - 1));
    if (status < 200 || status >= 300) {
        throw std::runtime_error("Kubernetes API request failed with status " + std::to_string(status));
    }

    return response.substr(pos + delimiter.size());
}

std::optional<std::string> FetchPodJson(const K8sClientOptions& options, const K8sQuery& query) {
    K8sResponseFetcher fetcher_copy;
    {
        std::lock_guard lock(FetcherMutex());
        fetcher_copy = Fetcher();
    }
    if (fetcher_copy) {
        return fetcher_copy(options, query);
    }

    if (options.api_server_host.empty()) {
        throw std::runtime_error("KUBERNETES_SERVICE_HOST is not set");
    }
    const std::string token = Trim(ReadFile(options.token_path));
    const std::string response = PerformHttpsGet(options, query, token);
    return ExtractBody(response);
}

std::optional<std::string> ReadString(const Json& object, const char* key) {
    if (!object.contains(key)) {
        return std::nullopt;
    }
    const auto& value = object.at(key);
    if (!value.is_string()) {
        return std::nullopt;
    }
    return value.get<std::string>();
}

void ReadStringMap(const Json& object, const char* key, std::map<std::string, std::string>& output) {
    if (!object.contains(key)) {
        return;
    }
    const auto& value = object.at(key);
    if (!value.is_object()) {
        return;
    }
    for (const auto& [name, item] : value.items()) {
        if (item.is_string()) {
            output.emplace(name, item.get<std::string>());
        }
    }
}

}  // namespace

void SetK8sResponseFetcherForTesting(K8sResponseFetcher fetcher) {
    std::lock_guard lock(FetcherMutex());
    Fetcher() = std::move(fetcher);
}

std::string BuildK8sApiEndpoint(std::string_view host, std::string_view port) {
    return "https://" + std::string(host) + ":" + std::string(port);
}

std::string BuildK8sApiEndpoint(std::string_view host, std::uint16_t port) {
    return BuildK8sApiEndpoint(host, std::to_string(port));
}

std::optional<PodInfo> ParsePodInfo(std::string_view json) {
    const auto parsed = Json::parse(std::string(json), nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return std::nullopt;
    }

    const auto metadata_it = parsed.find("metadata");
    const auto spec_it = parsed.find("spec");
    const auto status_it = parsed.find("status");
    if (metadata_it == parsed.end() || !metadata_it->is_object()) {
        return std::nullopt;
    }

    PodInfo info;
    auto name = ReadString(*metadata_it, "name");
    auto namespace_name = ReadString(*metadata_it, "namespace");
    if (!name || !namespace_name) {
        return std::nullopt;
    }
    info.name = std::move(*name);
    info.namespace_name = std::move(*namespace_name);

    if (spec_it != parsed.end() && spec_it->is_object()) {
        if (auto node_name = ReadString(*spec_it, "nodeName")) {
            info.node_name = std::move(*node_name);
        }
    }

    if (status_it != parsed.end() && status_it->is_object()) {
        if (auto phase = ReadString(*status_it, "phase")) {
            info.phase = std::move(*phase);
            info.running = (info.phase == "Running");
        }
    }

    ReadStringMap(*metadata_it, "labels", info.labels);
    ReadStringMap(*metadata_it, "annotations", info.annotations);
    return info;
}

PodInfo FetchPodInfo(const K8sQuery& query) {
    return FetchPodInfo(query, LoadDefaultOptions());
}

PodInfo FetchPodInfo(const K8sQuery& query, const K8sClientOptions& options) {
    const auto json = FetchPodJson(options, query);
    if (!json) {
        throw std::runtime_error("Kubernetes API response fetcher returned no data");
    }
    const auto parsed = ParsePodInfo(*json);
    if (!parsed) {
        throw std::runtime_error("failed to parse Kubernetes pod response");
    }
    return *parsed;
}

}  // namespace inline_proxy
