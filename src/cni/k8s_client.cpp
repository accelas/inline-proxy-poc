#include "cni/k8s_client.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <fstream>
#include <mutex>
#include <memory>
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

std::string FormatHostLiteral(std::string_view host) {
    if (host.empty()) {
        return std::string(host);
    }
    if (host.front() == '[' && host.back() == ']') {
        return std::string(host);
    }
    if (host.find(':') != std::string_view::npos) {
        return "[" + std::string(host) + "]";
    }
    return std::string(host);
}

std::string BuildHostHeader(const K8sClientOptions& options) {
    const std::string host = FormatHostLiteral(options.api_server_host);
    if (options.api_server_port.empty() || options.api_server_port == "443") {
        return host;
    }
    return host + ":" + options.api_server_port;
}

std::string BuildHttpRequest(const K8sClientOptions& options, const K8sQuery& query, const std::string& token) {
    std::ostringstream request;
    request << "GET " << BuildPodPath(query) << " HTTP/1.1\r\n";
    request << "Host: " << BuildHostHeader(options) << "\r\n";
    request << "Authorization: Bearer " << token << "\r\n";
    request << "Accept: application/json\r\n";
    request << "Connection: close\r\n\r\n";
    return request.str();
}

bool IsTimeoutErrno(int error) {
    return error == EAGAIN || error == EWOULDBLOCK || error == ETIMEDOUT;
}

bool WaitForFd(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, static_cast<int>(remaining.count()));
        if (rc > 0) {
            return true;
        }
        if (rc == 0) {
            return false;
        }
        if (errno != EINTR) {
            throw std::runtime_error("poll failed while waiting for Kubernetes API I/O");
        }
    }
}

int SslConnectWithTimeout(SSL* ssl, int fd, std::chrono::steady_clock::time_point deadline) {
    while (true) {
        const int rc = SSL_connect(ssl);
        if (rc == 1) {
            return rc;
        }
        const int error = SSL_get_error(ssl, rc);
        if (error == SSL_ERROR_WANT_READ) {
            if (!WaitForFd(fd, POLLIN, deadline)) {
                throw std::runtime_error("timed out negotiating TLS with Kubernetes API server");
            }
            continue;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            if (!WaitForFd(fd, POLLOUT, deadline)) {
                throw std::runtime_error("timed out negotiating TLS with Kubernetes API server");
            }
            continue;
        }
        if (error == SSL_ERROR_SYSCALL && IsTimeoutErrno(errno)) {
            throw std::runtime_error("timed out negotiating TLS with Kubernetes API server");
        }
        throw std::runtime_error("failed to negotiate TLS with Kubernetes API server");
    }
}

void SslWriteAllWithTimeout(SSL* ssl, int fd, std::chrono::steady_clock::time_point deadline, std::string_view data) {
    const char* cursor = data.data();
    std::size_t remaining = data.size();
    while (remaining > 0) {
        const int rc = SSL_write(ssl, cursor, static_cast<int>(remaining));
        if (rc > 0) {
            cursor += rc;
            remaining -= static_cast<std::size_t>(rc);
            continue;
        }
        const int error = SSL_get_error(ssl, rc);
        if (error == SSL_ERROR_WANT_READ) {
            if (!WaitForFd(fd, POLLIN, deadline)) {
                throw std::runtime_error("timed out sending Kubernetes API request");
            }
            continue;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            if (!WaitForFd(fd, POLLOUT, deadline)) {
                throw std::runtime_error("timed out sending Kubernetes API request");
            }
            continue;
        }
        if (error == SSL_ERROR_SYSCALL && IsTimeoutErrno(errno)) {
            throw std::runtime_error("timed out sending Kubernetes API request");
        }
        throw std::runtime_error("failed to send Kubernetes API request");
    }
}

std::string SslReadAllWithTimeout(SSL* ssl, int fd, std::chrono::steady_clock::time_point deadline) {
    std::string response;
    char buffer[4096];
    while (true) {
        const int rc = SSL_read(ssl, buffer, sizeof(buffer));
        if (rc > 0) {
            response.append(buffer, buffer + rc);
            continue;
        }
        const int error = SSL_get_error(ssl, rc);
        if (error == SSL_ERROR_ZERO_RETURN) {
            break;
        }
        if (error == SSL_ERROR_WANT_READ) {
            if (!WaitForFd(fd, POLLIN, deadline)) {
                throw std::runtime_error("timed out waiting for Kubernetes API response");
            }
            continue;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            if (!WaitForFd(fd, POLLOUT, deadline)) {
                throw std::runtime_error("timed out waiting for Kubernetes API response");
            }
            continue;
        }
        if (error == SSL_ERROR_SYSCALL && IsTimeoutErrno(errno)) {
            throw std::runtime_error("timed out waiting for Kubernetes API response");
        }
        throw std::runtime_error("failed to read Kubernetes API response");
    }
    return response;
}

int ConnectTcp(const std::string& host, const std::string& port, std::chrono::milliseconds timeout) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* results = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &results);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") + ::gai_strerror(rc));
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int fd = -1;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        fd = ::socket(it->ai_family, it->ai_socktype | SOCK_NONBLOCK, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        if (errno != EINPROGRESS) {
            ::close(fd);
            fd = -1;
            continue;
        }
        if (!WaitForFd(fd, POLLOUT, deadline)) {
            ::close(fd);
            fd = -1;
            break;
        }
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0 || socket_error != 0) {
            ::close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    ::freeaddrinfo(results);
    if (fd < 0) {
        throw std::runtime_error("failed to connect to Kubernetes API server within timeout");
    }

    return fd;
}

std::string PerformHttpsGet(const K8sClientOptions& options, const K8sQuery& query, const std::string& token) {
    class UniqueFd {
    public:
        explicit UniqueFd(int fd) : fd_(fd) {}
        ~UniqueFd() {
            if (fd_ >= 0) {
                ::close(fd_);
            }
        }

        UniqueFd(const UniqueFd&) = delete;
        UniqueFd& operator=(const UniqueFd&) = delete;
        UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
        UniqueFd& operator=(UniqueFd&& other) noexcept {
            if (this != &other) {
                reset(std::exchange(other.fd_, -1));
            }
            return *this;
        }

        int get() const { return fd_; }

    private:
        void reset(int fd) {
            if (fd_ >= 0) {
                ::close(fd_);
            }
            fd_ = fd;
        }

        int fd_ = -1;
    };

    const UniqueFd fd(ConnectTcp(options.api_server_host, options.api_server_port, options.timeout));

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);
    if (!ctx) {
        throw std::runtime_error("failed to create SSL context");
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(ctx.get(), options.ca_path.string().c_str(), nullptr) != 1) {
        throw std::runtime_error("failed to load Kubernetes CA bundle");
    }

    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), &SSL_free);
    if (!ssl) {
        throw std::runtime_error("failed to create SSL object");
    }
    if (SSL_set_fd(ssl.get(), fd.get()) != 1) {
        throw std::runtime_error("failed to bind TLS object to socket");
    }
    if (SSL_set_tlsext_host_name(ssl.get(), options.api_server_host.c_str()) != 1) {
        throw std::runtime_error("failed to configure TLS SNI");
    }
    if (SSL_set1_host(ssl.get(), options.api_server_host.c_str()) != 1) {
        throw std::runtime_error("failed to configure TLS hostname verification");
    }

    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    SslConnectWithTimeout(ssl.get(), fd.get(), deadline);

    const std::string request = BuildHttpRequest(options, query, token);
    SslWriteAllWithTimeout(ssl.get(), fd.get(), deadline, request);
    const std::string response = SslReadAllWithTimeout(ssl.get(), fd.get(), deadline);

    (void)SSL_shutdown(ssl.get());
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
    if (options.timeout.count() <= 0) {
        throw std::runtime_error("Kubernetes client timeout must be positive");
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
    return "https://" + FormatHostLiteral(host) + ":" + std::string(port);
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
