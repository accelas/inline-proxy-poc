#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <netdb.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cni/k8s_client.hpp"

namespace {

std::atomic<bool> g_delay_localhost_dns{false};

using RealGetAddrInfoFn = int (*)(const char*, const char*, const addrinfo*, addrinfo**);

RealGetAddrInfoFn RealGetAddrInfo() {
    static const RealGetAddrInfoFn fn = []() -> RealGetAddrInfoFn {
        dlerror();
        void* symbol = dlsym(RTLD_NEXT, "getaddrinfo");
        if (!symbol) {
            std::fprintf(stderr, "failed to resolve real getaddrinfo: %s\n", dlerror());
            std::abort();
        }
        return reinterpret_cast<RealGetAddrInfoFn>(symbol);
    }();
    return fn;
}

int ParsePort(const char* service, uint16_t* port) {
    if (!service || *service == '\0') {
        return 0;
    }
    char* end = nullptr;
    const long parsed = std::strtol(service, &end, 10);
    if (!end || *end != '\0' || parsed < 0 || parsed > 65535) {
        return EAI_SERVICE;
    }
    *port = static_cast<uint16_t>(parsed);
    return 0;
}

addrinfo* MakeAddrInfoNode(int family, uint16_t port, const addrinfo* hints) {
    auto* node = static_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
    if (!node) {
        return nullptr;
    }

    node->ai_family = family;
    node->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
    node->ai_protocol = hints ? hints->ai_protocol : 0;

    if (family == AF_INET6) {
        auto* address = static_cast<sockaddr_in6*>(std::calloc(1, sizeof(sockaddr_in6)));
        if (!address) {
            std::free(node);
            return nullptr;
        }
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(port);
        if (::inet_pton(AF_INET6, "::1", &address->sin6_addr) != 1) {
            std::free(address);
            std::free(node);
            return nullptr;
        }
        node->ai_addrlen = sizeof(sockaddr_in6);
        node->ai_addr = reinterpret_cast<sockaddr*>(address);
    } else {
        auto* address = static_cast<sockaddr_in*>(std::calloc(1, sizeof(sockaddr_in)));
        if (!address) {
            std::free(node);
            return nullptr;
        }
        address->sin_family = AF_INET;
        address->sin_port = htons(port);
        if (::inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) != 1) {
            std::free(address);
            std::free(node);
            return nullptr;
        }
        node->ai_addrlen = sizeof(sockaddr_in);
        node->ai_addr = reinterpret_cast<sockaddr*>(address);
    }

    return node;
}

int ResolveLocalhostForTests(const char* service, const addrinfo* hints, addrinfo** res) {
    *res = nullptr;

    uint16_t port = 0;
    const int port_rc = ParsePort(service, &port);
    if (port_rc != 0) {
        return port_rc;
    }

    const bool want_v6 = !hints || hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET6;
    const bool want_v4 = !hints || hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET;

    addrinfo* head = nullptr;
    addrinfo** tail = &head;

    if (want_v6) {
        *tail = MakeAddrInfoNode(AF_INET6, port, hints);
        if (!*tail) {
            ::freeaddrinfo(head);
            return EAI_MEMORY;
        }
        tail = &((*tail)->ai_next);
    }

    if (want_v4) {
        *tail = MakeAddrInfoNode(AF_INET, port, hints);
        if (!*tail) {
            ::freeaddrinfo(head);
            return EAI_MEMORY;
        }
    }

    *res = head;
    return 0;
}

}  // namespace

extern "C" int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    if (node && std::strcmp(node, "localhost") == 0) {
        if (g_delay_localhost_dns.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        return ResolveLocalhostForTests(service, hints, res);
    }
    return RealGetAddrInfo()(node, service, hints, res);
}

namespace {

struct TempCertBundle {
    std::filesystem::path directory;
    std::filesystem::path cert_path;
    std::filesystem::path key_path;
    std::filesystem::path token_path;
};

TempCertBundle CreateTempCertBundle() {
    const auto base = std::filesystem::temp_directory_path() /
                      ("inline-proxy-k8s-client-" + std::to_string(::getpid()) + "-" + std::to_string(::getpid() ^ 0x5a5a));
    std::filesystem::create_directories(base);
    return TempCertBundle{.directory = base,
                          .cert_path = base / "server.crt",
                          .key_path = base / "server.key",
                          .token_path = base / "token"};
}

static constexpr const char kTestCertPem[] = R"PEM(
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIURXEIq+cxfX4ILQQEGMfBMl9NBIwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQxODIzMzUwOVoXDTI2MDQx
OTIzMzUwOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAk0fp4LJVqzfnax1lNQX16G0tfl2RkcVDC/J/uc3rkUe9
31kmCZOZdlNxJznT1qmdvAuQ9XvhqmaVvFra5kg54/lIFJPGuLXMbyp+u8RLF/f8
hgjyGqTR+/755DzhKxK83uOoX57JNoTU8MnRHAMjkUOyrUAmvTpc3vV7CQMWaU6q
kAvay6PpFig7XAoOal93tmkwPhFcH6akX0XpsngB5k348mwycvw8gYWoQrXDLAMM
kVxFt7DupwfkSS3myrZdoqaxGi2pvUmlypuVl0F/XLk+ilfG9LUtxTf82UXNHWFP
XmEX4sQA832OGzMfqp1ncpoH02D3jtv557fITwGZGwIDAQABo1MwUTAdBgNVHQ4E
FgQUn0Jlk2KS+tiL4qeI6m2UY0Jvi7MwHwYDVR0jBBgwFoAUn0Jlk2KS+tiL4qeI
6m2UY0Jvi7MwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEACVZH
IBbpqejeTpIjDLv/JwRxiwSnXj7XhKNZSBeqMFFO/wCtztuLE7mvZt9+cWzfmV7x
fnprss2rkY/Lf6Utgc2IV0ffiAO3UyqvEwkOwD0SqiWZcsqIhZDtJfwA4kFGj2OA
f4gJ80xxKfnYpE15nNRIrzMItKALXDGfD9yCTZbNFRk+rqnsjlBwAZpwwakTPO+1
kDPntmqhVRvezhmhDdK4fcm0j17APQXcs10LmNucG151WGk3GnyrkBsZ/qruWkI/
aX1jD4SF9vUOYtZj1kCwTy+BaKBd1UezF8xC1urS61DcWYWmrOb4Y82FqgdAuFoO
y03Gfd90OiILJHSKcQ==
-----END CERTIFICATE-----
)PEM";

static constexpr const char kTestKeyPem[] = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTR+ngslWrN+dr
HWU1BfXobS1+XZGRxUML8n+5zeuRR73fWSYJk5l2U3EnOdPWqZ28C5D1e+GqZpW8
WtrmSDnj+UgUk8a4tcxvKn67xEsX9/yGCPIapNH7/vnkPOErErze46hfnsk2hNTw
ydEcAyORQ7KtQCa9Olze9XsJAxZpTqqQC9rLo+kWKDtcCg5qX3e2aTA+EVwfpqRf
RemyeAHmTfjybDJy/DyBhahCtcMsAwyRXEW3sO6nB+RJLebKtl2iprEaLam9SaXK
m5WXQX9cuT6KV8b0tS3FN/zZRc0dYU9eYRfixADzfY4bMx+qnWdymgfTYPeO2/nn
t8hPAZkbAgMBAAECggEAB/3jes4CfbTItGnBwk5NU9bfcezEMjY+LJ70f6cPrMWe
pR4dGnDtZ1vLbIxOlTvanh0R48LcnGv48mG1thWI5U4eCKvPdoS65UoCMCXMc1kB
VV6VOzfirbteC5yiv+fCODqp5MJk0GCwff5df+51rB4RyyU2KkIepE81ZWhK+4d0
Vn7Yz437LU2QTDKS27MulYvblGSjVRW4KFfhH6KMCXHnZbKV3dnF9w37mDIQxIFc
k+Xpbg25Cd3VNGcTqYXXj40YIkZNfkrAXhxyJ5rJLPxT68ToMV3Oqdo3031xXQPw
krdeG21nwUIhu4uyq4GMFFfTowC4jeMt0JvT6Y43WQKBgQDEebdF+AU8FsepezzQ
vUXsHbRrqobzdz0EBxCnK5rWW3z606m6rVIPafDFhNpy8LQ6uJbCZcgS13fRoHq4
XHCs8WV2d/2x47Ix6yjH/Uen2fdFtmwDlMncy3pnngzpOzkUlWbm1s4/CjiNholD
gwrXuwwaj01bemwOptcsaOxyQwKBgQC/5sHcSx9NDbiv/HRIwStgtiEWk4BBG84X
dKDlUFVBz53noPNUsdurPSON8Hn6DrC0dQV8gfNKSxpR603gzAMGDaz+QeJuIX1Y
er07L97WmncitKSIvr0oeJRME7GTc8c+cfj38HW235JFBzZ7+fb3SoYeHBwWjxls
WsI3ePCsSQKBgQCXlNhDESDoxSJxrXS0DvLdQeWqkzvepoXaj6DXeJrS+m6oDZkL
PyDqZ2+s09y9hNtn2nXlsST09GuqvUcw6ZC8vNjs15JRJjyaqrUh5lTcORu/Gwim
kqpSwGHFg3iukFRvfvyO5/bjR/1tovhPr9AztEmYTCsAgqjPfQTRbHnPhQKBgQCW
rdc8ZVQPiZ2huaWI1vx7dKaodmr3NKDvM+l+BUTcZuwCyxMlRn5Ih7oaIl90ZAKF
v3juWY8xn6Tr+8nrn+Uj5KsX/Z2QggVM6xsYlS7w7NpsytCCetpGI9+1mKUPNZKV
yqIF9K5JSGUuhEpYsF4lsEN88u9vGy+IL/9d1T2M2QKBgGJr/od4n6zmcMi4qOMS
e7un4ywMUrvi27g4IKXfBZo8Lm2X+JoBQ8J9q0A9bSNaF/42pQUq4TfChqZPZqMD
jkix5J5hi+dJwWsmkMbWX4WDTPGH07oBr7OyC7QvbDqGyOzxGz3DNLG0FfPNPvWf
f1MMHHg/I9zV/mKsMfTSYnDu
-----END PRIVATE KEY-----
)PEM";

void WritePemFiles(const TempCertBundle& bundle) {
    {
        std::ofstream cert(bundle.cert_path);
        if (!cert) {
            throw std::runtime_error("failed to open cert file");
        }
        cert << kTestCertPem;
    }
    {
        std::ofstream key(bundle.key_path);
        if (!key) {
            throw std::runtime_error("failed to open key file");
        }
        key << kTestKeyPem;
    }
    {
        std::ofstream token(bundle.token_path);
        if (!token) {
            throw std::runtime_error("failed to write token file");
        }
        token << "test-token\n";
    }
}

int CountOpenFileDescriptors() {
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
        (void)entry;
        ++count;
    }
    return count;
}

class ScopedEnvVar {
public:
    ScopedEnvVar(const char* name, const std::optional<std::string>& value) : name_(name) {
        if (const char* current = std::getenv(name_)) {
            old_value_ = std::string(current);
        }
        if (value.has_value()) {
            ::setenv(name_, value->c_str(), 1);
        } else {
            ::unsetenv(name_);
        }
    }

    ~ScopedEnvVar() {
        if (old_value_.has_value()) {
            ::setenv(name_, old_value_->c_str(), 1);
        } else {
            ::unsetenv(name_);
        }
    }

private:
    const char* name_;
    std::optional<std::string> old_value_;
};

class StallingTlsServer {
public:
    explicit StallingTlsServer(const TempCertBundle& bundle) {
        std::promise<uint16_t> port_promise;
        auto port_future = port_promise.get_future();
        thread_ = std::thread([this, bundle, promise = std::move(port_promise)]() mutable {
            Run(bundle, std::move(promise));
        });
        port_ = port_future.get();
    }

    ~StallingTlsServer() {
        stop_ = true;
        if (client_fd_ >= 0) {
            ::shutdown(client_fd_, SHUT_RDWR);
            ::close(client_fd_);
        }
        if (server_fd_ >= 0) {
            ::shutdown(server_fd_, SHUT_RDWR);
            ::close(server_fd_);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    uint16_t port() const { return port_; }

private:
    void Run(const TempCertBundle& bundle, std::promise<uint16_t> promise) {
        try {
            server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (server_fd_ < 0) {
                throw std::runtime_error("socket failed");
            }
            int one = 1;
            if (::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
                throw std::runtime_error("setsockopt failed");
            }

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = 0;
            if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
                throw std::runtime_error("inet_pton failed");
            }
            if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
                throw std::runtime_error("bind failed");
            }
            if (::listen(server_fd_, 1) != 0) {
                throw std::runtime_error("listen failed");
            }

            socklen_t len = sizeof(addr);
            if (::getsockname(server_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
                throw std::runtime_error("getsockname failed");
            }
            promise.set_value(ntohs(addr.sin_port));

            client_fd_ = ::accept(server_fd_, nullptr, nullptr);
            if (client_fd_ < 0) {
                throw std::runtime_error("accept failed");
            }

            SSL_CTX* ctx_raw = SSL_CTX_new(TLS_server_method());
            if (!ctx_raw) {
                throw std::runtime_error("SSL_CTX_new failed");
            }
            std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(ctx_raw, &SSL_CTX_free);
            if (SSL_CTX_use_certificate_file(ctx.get(), bundle.cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error("SSL_CTX_use_certificate_file failed");
            }
            if (SSL_CTX_use_PrivateKey_file(ctx.get(), bundle.key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed");
            }

            SSL* ssl_raw = SSL_new(ctx.get());
            if (!ssl_raw) {
                throw std::runtime_error("SSL_new failed");
            }
            std::unique_ptr<SSL, decltype(&SSL_free)> ssl(ssl_raw, &SSL_free);
            if (SSL_set_fd(ssl.get(), client_fd_) != 1) {
                throw std::runtime_error("SSL_set_fd failed");
            }
            if (SSL_accept(ssl.get()) != 1) {
                throw std::runtime_error("SSL_accept failed");
            }

            char buffer[4096];
            (void)SSL_read(ssl.get(), buffer, sizeof(buffer));
            while (!stop_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        } catch (...) {
            try {
                promise.set_exception(std::current_exception());
            } catch (...) {
            }
        }
    }

    std::thread thread_;
    int server_fd_ = -1;
    int client_fd_ = -1;
    std::atomic<bool> stop_{false};
    uint16_t port_ = 0;
};

class BackloggedDualStackServer {
public:
    BackloggedDualStackServer() {
        server_v6_fd_ = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (server_v6_fd_ < 0) {
            throw std::runtime_error("failed to create IPv6 listener");
        }
        int one = 1;
        if (::setsockopt(server_v6_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
            throw std::runtime_error("failed to set IPv6 SO_REUSEADDR");
        }
        if (::setsockopt(server_v6_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) != 0) {
            throw std::runtime_error("failed to set IPV6_V6ONLY");
        }

        sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = 0;
        if (::inet_pton(AF_INET6, "::1", &addr6.sin6_addr) != 1) {
            throw std::runtime_error("inet_pton(::1) failed");
        }
        if (::bind(server_v6_fd_, reinterpret_cast<sockaddr*>(&addr6), sizeof(addr6)) != 0) {
            throw std::runtime_error("failed to bind IPv6 listener");
        }
        if (::listen(server_v6_fd_, 1) != 0) {
            throw std::runtime_error("failed to listen on IPv6 listener");
        }
        socklen_t len6 = sizeof(addr6);
        if (::getsockname(server_v6_fd_, reinterpret_cast<sockaddr*>(&addr6), &len6) != 0) {
            throw std::runtime_error("failed to read IPv6 listener port");
        }
        port_ = ntohs(addr6.sin6_port);

        server_v4_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (server_v4_fd_ < 0) {
            throw std::runtime_error("failed to create IPv4 listener");
        }
        if (::setsockopt(server_v4_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
            throw std::runtime_error("failed to set IPv4 SO_REUSEADDR");
        }

        sockaddr_in addr4{};
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port_);
        if (::inet_pton(AF_INET, "127.0.0.1", &addr4.sin_addr) != 1) {
            throw std::runtime_error("inet_pton(127.0.0.1) failed");
        }
        if (::bind(server_v4_fd_, reinterpret_cast<sockaddr*>(&addr4), sizeof(addr4)) != 0) {
            throw std::runtime_error("failed to bind IPv4 listener");
        }
        if (::listen(server_v4_fd_, 1) != 0) {
            throw std::runtime_error("failed to listen on IPv4 listener");
        }

        FillBacklog(AF_INET6, reinterpret_cast<const sockaddr*>(&addr6), sizeof(addr6));
        FillBacklog(AF_INET, reinterpret_cast<const sockaddr*>(&addr4), sizeof(addr4));
        if (ProbeBacklog(AF_INET6, reinterpret_cast<const sockaddr*>(&addr6), sizeof(addr6)) ||
            ProbeBacklog(AF_INET, reinterpret_cast<const sockaddr*>(&addr4), sizeof(addr4))) {
            throw std::runtime_error("failed to saturate both listener backlogs");
        }
        if (held_connections_.size() < 16) {
            throw std::runtime_error("failed to saturate both listener backlogs");
        }
    }

    ~BackloggedDualStackServer() {
        for (int fd : held_connections_) {
            ::close(fd);
        }
        if (server_v4_fd_ >= 0) {
            ::close(server_v4_fd_);
        }
        if (server_v6_fd_ >= 0) {
            ::close(server_v6_fd_);
        }
    }

    uint16_t port() const { return port_; }

private:
    void FillBacklog(int family, const sockaddr* address, socklen_t address_len) {
        std::vector<int> pending_connections;
        for (int attempt = 0; attempt < 96; ++attempt) {
            int fd = ::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0) {
                throw std::runtime_error("failed to create backlog filler socket");
            }
            const int rc = ::connect(fd, address, address_len);
            if (rc != 0 && errno != EINPROGRESS) {
                ::close(fd);
                continue;
            }
            pending_connections.push_back(fd);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        for (int fd : pending_connections) {
            held_connections_.push_back(fd);
        }
    }

    bool ProbeBacklog(int family, const sockaddr* address, socklen_t address_len) {
        int fd = ::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) {
            throw std::runtime_error("failed to create backlog probe socket");
        }

        const int rc = ::connect(fd, address, address_len);
        if (rc == 0) {
            ::close(fd);
            return true;
        }
        if (rc != 0 && errno != EINPROGRESS) {
            ::close(fd);
            return true;
        }

        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        const int poll_rc = ::poll(&pfd, 1, 25);
        ::close(fd);
        return poll_rc > 0;
    }

    int server_v6_fd_ = -1;
    int server_v4_fd_ = -1;
    uint16_t port_ = 0;
    std::vector<int> held_connections_;
};

}  // namespace

TEST(K8sClientTest, ParsesPodLookupResponse) {
    std::string json = R"({
        "apiVersion":"v1",
        "kind":"Pod",
        "metadata":{
            "name":"proxy-1",
            "namespace":"inline-proxy-system",
            "labels":{"app":"inline-proxy"},
            "annotations":{"inline-proxy.example.com/enabled":"true"}
        },
        "spec":{"nodeName":"worker-1"},
        "status":{"phase":"Running"}
    })";

    auto pod = inline_proxy::ParsePodInfo(json);
    ASSERT_TRUE(pod.has_value());
    EXPECT_EQ(pod->name, "proxy-1");
    EXPECT_EQ(pod->namespace_name, "inline-proxy-system");
    EXPECT_EQ(pod->node_name, "worker-1");
    EXPECT_TRUE(pod->running);
    EXPECT_EQ(pod->labels.at("app"), "inline-proxy");
    EXPECT_EQ(pod->annotations.at("inline-proxy.example.com/enabled"), "true");
}

TEST(K8sClientTest, BuildsDefaultInClusterApiEndpoint) {
    const auto endpoint = inline_proxy::BuildK8sApiEndpoint("10.0.0.1", "443");
    EXPECT_EQ(endpoint, "https://10.0.0.1:443");
}

TEST(K8sClientTest, BuildsIpv6ApiEndpointWithBrackets) {
    const auto endpoint = inline_proxy::BuildK8sApiEndpoint("2001:db8::1", "443");
    EXPECT_EQ(endpoint, "https://[2001:db8::1]:443");
}

TEST(K8sClientTest, FetchPodInfoUsesInjectedFetcher) {
    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    inline_proxy::SetK8sResponseFetcherForTesting(
        [](const inline_proxy::K8sClientOptions&, const inline_proxy::K8sQuery&) {
            return std::optional<std::string>(R"({
                "metadata":{"name":"proxy-1","namespace":"inline-proxy-system"},
                "spec":{"nodeName":"worker-1"},
                "status":{"phase":"Running"}
            })");
        });

    const auto pod = inline_proxy::FetchPodInfo(query);
    EXPECT_EQ(pod.name, "proxy-1");
    EXPECT_EQ(pod.node_name, "worker-1");
    EXPECT_TRUE(pod.running);

    inline_proxy::SetK8sResponseFetcherForTesting({});
}

TEST(K8sClientTest, FetchPodInfoLoadsDefaultOptionsFromKubeconfig) {
    const auto base = std::filesystem::temp_directory_path() /
                      ("inline-proxy-kubeconfig-" + std::to_string(::getpid()) + "-default");
    std::filesystem::create_directories(base);
    const auto kubeconfig_path = base / "kubeconfig";
    const auto ca_path = base / "ca.crt";
    const auto client_cert_path = base / "client.crt";
    const auto client_key_path = base / "client.key";

    {
        std::ofstream kubeconfig(kubeconfig_path);
        ASSERT_TRUE(static_cast<bool>(kubeconfig));
        kubeconfig << "apiVersion: v1\n"
                   << "clusters:\n"
                   << "- cluster:\n"
                   << "    server: https://127.0.0.1:6443\n"
                   << "    certificate-authority: " << ca_path.string() << "\n"
                   << "  name: local\n"
                   << "users:\n"
                   << "- name: user\n"
                   << "  user:\n"
                   << "    client-certificate: " << client_cert_path.string() << "\n"
                   << "    client-key: " << client_key_path.string() << "\n";
    }

    ScopedEnvVar service_host("KUBERNETES_SERVICE_HOST", std::nullopt);
    ScopedEnvVar service_port("KUBERNETES_SERVICE_PORT", std::nullopt);
    ScopedEnvVar token_path("INLINE_PROXY_K8S_TOKEN_PATH", std::nullopt);
    ScopedEnvVar ca_override("INLINE_PROXY_K8S_CA_PATH", std::nullopt);
    ScopedEnvVar kubeconfig_override("INLINE_PROXY_KUBECONFIG_PATH", kubeconfig_path.string());

    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    inline_proxy::SetK8sResponseFetcherForTesting(
        [&](const inline_proxy::K8sClientOptions& options, const inline_proxy::K8sQuery&) {
            EXPECT_EQ(options.api_server_host, "127.0.0.1");
            EXPECT_EQ(options.api_server_port, "6443");
            EXPECT_EQ(options.ca_path, ca_path);
            EXPECT_EQ(options.client_cert_path, client_cert_path);
            EXPECT_EQ(options.client_key_path, client_key_path);
            return std::optional<std::string>(R"({
                "metadata":{"name":"proxy-1","namespace":"inline-proxy-system"},
                "spec":{"nodeName":"worker-1"},
                "status":{"phase":"Running"}
            })");
        });

    const auto pod = inline_proxy::FetchPodInfo(query);
    EXPECT_EQ(pod.name, "proxy-1");
    EXPECT_EQ(pod.node_name, "worker-1");
    EXPECT_TRUE(pod.running);

    inline_proxy::SetK8sResponseFetcherForTesting({});
}

TEST(K8sClientTest, TimesOutWhenApiserverStopsRespondingAfterTlsHandshake) {
    auto bundle = CreateTempCertBundle();
    WritePemFiles(bundle);

    StallingTlsServer server(bundle);

    inline_proxy::K8sClientOptions options;
    options.api_server_host = "localhost";
    options.api_server_port = std::to_string(server.port());
    options.token_path = bundle.token_path;
    options.ca_path = bundle.cert_path;
    options.timeout = std::chrono::milliseconds(100);

    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW((inline_proxy::FetchPodInfo(query, options)), std::runtime_error);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 2);
}

TEST(K8sClientTest, CleansUpSocketsAndTlsResourcesWhenRequestTimesOut) {
    const int baseline_fd_count = CountOpenFileDescriptors();

    {
        auto bundle = CreateTempCertBundle();
        WritePemFiles(bundle);

        {
            StallingTlsServer server(bundle);

            inline_proxy::K8sClientOptions options;
            options.api_server_host = "localhost";
            options.api_server_port = std::to_string(server.port());
            options.token_path = bundle.token_path;
            options.ca_path = bundle.cert_path;
            options.timeout = std::chrono::milliseconds(100);

            const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

            EXPECT_THROW((inline_proxy::FetchPodInfo(query, options)), std::runtime_error);
        }
    }

    EXPECT_EQ(CountOpenFileDescriptors(), baseline_fd_count);
}

TEST(K8sClientTest, EnforcesSingleTimeoutBudgetAcrossResolvedAddresses) {
    auto bundle = CreateTempCertBundle();
    WritePemFiles(bundle);
    BackloggedDualStackServer server;

    inline_proxy::K8sClientOptions options;
    options.api_server_host = "localhost";
    options.api_server_port = std::to_string(server.port());
    options.token_path = bundle.token_path;
    options.ca_path = bundle.cert_path;
    options.timeout = std::chrono::milliseconds(100);

    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW((inline_proxy::FetchPodInfo(query, options)), std::runtime_error);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 160) << "elapsed=" << elapsed.count() << "ms";
}

TEST(K8sClientTest, TimesOutAcrossDnsResolutionAndRequestPhases) {
    auto bundle = CreateTempCertBundle();
    WritePemFiles(bundle);
    StallingTlsServer server(bundle);

    struct DnsDelayGuard {
        ~DnsDelayGuard() { g_delay_localhost_dns.store(false, std::memory_order_relaxed); }
    } guard;

    g_delay_localhost_dns.store(true, std::memory_order_relaxed);

    inline_proxy::K8sClientOptions options;
    options.api_server_host = "localhost";
    options.api_server_port = std::to_string(server.port());
    options.token_path = bundle.token_path;
    options.ca_path = bundle.cert_path;
    options.timeout = std::chrono::milliseconds(100);

    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW((inline_proxy::FetchPodInfo(query, options)), std::runtime_error);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    EXPECT_LT(elapsed.count(), 160) << "elapsed=" << elapsed.count() << "ms";
}
