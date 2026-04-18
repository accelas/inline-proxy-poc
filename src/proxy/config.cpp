#include "proxy/config.hpp"

#include <algorithm>
#include <cstddef>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "proxy/admin_http.hpp"
#include "proxy/interface_registry.hpp"
#include "proxy/relay_session.hpp"
#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"

extern char** environ;

namespace inline_proxy {
namespace {

constexpr std::string_view kAdminPortEnv = "INLINE_PROXY_ADMIN_PORT";
constexpr std::string_view kTransparentPortEnv = "INLINE_PROXY_TRANSPARENT_PORT";
constexpr std::string_view kAdminPrefix = "--admin-port=";
constexpr std::string_view kTransparentPrefix = "--transparent-port=";
constexpr std::string_view kInlineProxyPrefix = "INLINE_PROXY_";

AdminSendHook& AdminSendHookRef() {
    static AdminSendHook hook = nullptr;
    return hook;
}

struct PlainListener {
    ScopedFd fd;

    bool ok() const noexcept {
        return fd.valid();
    }

    int fd_num() const noexcept {
        return fd.get();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

std::uint16_t ParsePortOrThrow(std::string_view value, std::string_view source) {
    unsigned int parsed = 0;
    const char* begin = value.data();
    const char* end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed == 0 || parsed > 65535U) {
        throw std::invalid_argument(std::string(source) + " must be a port number between 1 and 65535");
    }
    return static_cast<std::uint16_t>(parsed);
}

struct CliParseResult {
    bool admin_seen = false;
    bool transparent_seen = false;
};

CliParseResult ParseCliOverrides(ProxyConfig& cfg, int argc, char** argv) {
    CliParseResult seen;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i] ? argv[i] : "");
        if (arg.rfind(kAdminPrefix, 0) == 0) {
            cfg.admin_port = ParsePortOrThrow(arg.substr(kAdminPrefix.size()), kAdminPrefix);
            seen.admin_seen = true;
            continue;
        }
        if (arg.rfind(kTransparentPrefix, 0) == 0) {
            cfg.transparent_port = ParsePortOrThrow(arg.substr(kTransparentPrefix.size()), kTransparentPrefix);
            seen.transparent_seen = true;
            continue;
        }
        throw std::invalid_argument(std::string("unknown CLI flag: ") + std::string(arg));
    }
    return seen;
}

void ApplyOverride(ProxyConfig& cfg, std::string_view name, std::string_view value) {
    if (name == kAdminPortEnv) {
        cfg.admin_port = ParsePortOrThrow(value, kAdminPortEnv);
        return;
    }
    if (name == kTransparentPortEnv) {
        cfg.transparent_port = ParsePortOrThrow(value, kTransparentPortEnv);
        return;
    }
    throw std::invalid_argument(std::string("unknown env key: ") + std::string(name));
}

void ApplyEnvOverrides(ProxyConfig& cfg, std::initializer_list<ProxyConfig::EnvOverride> env) {
    for (const auto& [name, value] : env) {
        ApplyOverride(cfg, name, value);
    }
}

void ApplyProcessEnvOverrides(ProxyConfig& cfg, const CliParseResult& cli) {
    for (char** env = environ; env != nullptr && *env != nullptr; ++env) {
        std::string_view entry(*env);
        const std::size_t eq = entry.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }

        const std::string_view name = entry.substr(0, eq);
        if (name.rfind(kInlineProxyPrefix, 0) != 0) {
            continue;
        }

        if (name == kAdminPortEnv) {
            if (!cli.admin_seen) {
                cfg.admin_port = ParsePortOrThrow(entry.substr(eq + 1), kAdminPortEnv);
            }
            continue;
        }

        if (name == kTransparentPortEnv) {
            if (!cli.transparent_seen) {
                cfg.transparent_port = ParsePortOrThrow(entry.substr(eq + 1), kTransparentPortEnv);
            }
            continue;
        }

        throw std::invalid_argument(std::string("unknown env key: ") + std::string(name));
    }
}

PlainListener CreatePlainListener(const std::string& address, std::uint16_t port) {
    PlainListener listener;
    listener.fd.reset(::socket(AF_INET, SOCK_STREAM, 0));
    if (!listener.fd) {
        return listener;
    }

    const int reuse = 1;
    if (::setsockopt(listener.fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        return PlainListener{};
    }

    const auto bind_addr = MakeSockaddr4(address, port);
    if (bind_addr.ss_family != AF_INET) {
        return PlainListener{};
    }

    if (::bind(listener.fd.get(),
               reinterpret_cast<const sockaddr*>(&bind_addr),
               sizeof(sockaddr_in)) != 0) {
        return PlainListener{};
    }

    if (::listen(listener.fd.get(), 128) != 0) {
        return PlainListener{};
    }

    if (!SetNonBlocking(listener.fd.get())) {
        return PlainListener{};
    }

    return listener;
}

std::string HttpStatusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

std::string FormatHttpResponse(const AdminResponse& response) {
    std::string out;
    out += "HTTP/1.1 ";
    out += std::to_string(response.status);
    out += ' ';
    out += HttpStatusText(response.status);
    out += "\r\n";
    out += "Content-Type: ";
    out += response.content_type;
    out += "\r\n";
    out += "Content-Length: ";
    out += std::to_string(response.body.size());
    out += "\r\n";
    out += "Connection: close\r\n\r\n";
    out += response.body;
    return out;
}

bool RequestComplete(const std::string& request) {
    return request.find("\r\n\r\n") != std::string::npos || request.find("\n\n") != std::string::npos;
}

std::pair<std::string_view, std::string_view> ParseRequestLine(const std::string& request) {
    const auto line_end = request.find('\n');
    const std::string_view line = line_end == std::string::npos
        ? std::string_view(request)
        : std::string_view(request.data(), line_end);

    const auto method_end = line.find(' ');
    if (method_end == std::string_view::npos) {
        return {};
    }
    const auto path_end = line.find(' ', method_end + 1);
    if (path_end == std::string_view::npos) {
        return {};
    }
    return {line.substr(0, method_end), line.substr(method_end + 1, path_end - method_end - 1)};
}

class AdminConnection : public std::enable_shared_from_this<AdminConnection> {
public:
    AdminConnection(EventLoop& loop, ScopedFd fd, AdminHttp& admin_http)
        : loop_(loop), fd_(std::move(fd)), admin_http_(admin_http) {}

    void Arm() {
        auto weak = weak_from_this();
        handle_ = loop_.Register(
            fd_.get(),
            true,
            false,
            [weak] {
                if (auto self = weak.lock()) {
                    self->OnReadable();
                }
            },
            [weak] {
                if (auto self = weak.lock()) {
                    self->OnWritable();
                }
            },
            [weak](int) {
                if (auto self = weak.lock()) {
                    self->Close();
                }
            });
    }

    bool closed() const noexcept {
        return closed_;
    }

private:
    void OnReadable() {
        char buffer[4096];
        while (true) {
            const ssize_t n = ::read(fd_.get(), buffer, sizeof(buffer));
            if (n > 0) {
                request_.append(buffer, buffer + n);
                if (request_.size() > 16 * 1024) {
                    PrepareResponse(400, "request too large\n");
                    return;
                }
                if (RequestComplete(request_)) {
                    PrepareResponse();
                    return;
                }
                continue;
            }
            if (n == 0) {
                if (!request_.empty()) {
                    PrepareResponse();
                } else {
                    Close();
                }
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            Close();
            return;
        }
    }

    void OnWritable() {
        while (response_offset_ < response_.size()) {
            const ssize_t n = DoAdminSend(fd_.get(),
                                          response_.data() + response_offset_,
                                          response_.size() - response_offset_,
                                          MSG_NOSIGNAL);
            if (n > 0) {
                response_offset_ += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            Close();
            return;
        }
        Close();
    }

    void PrepareResponse(int status, std::string body) {
        response_ = FormatHttpResponse(AdminResponse{
            .status = status,
            .content_type = "text/plain; charset=utf-8",
            .body = std::move(body),
        });
        response_offset_ = 0;
        if (handle_) {
            handle_->Update(false, true);
        }
    }

    void PrepareResponse() {
        const auto [method, path] = ParseRequestLine(request_);
        if (method.empty() || path.empty()) {
            PrepareResponse(400, "bad request\n");
            return;
        }

        auto response = admin_http_.Handle(method, path);
        response_ = FormatHttpResponse(response);
        response_offset_ = 0;
        if (handle_) {
            handle_->Update(false, true);
        }
    }

    void Close() {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (handle_) {
            handle_.reset();
        }
        fd_.reset();
    }

    EventLoop& loop_;
    ScopedFd fd_;
    AdminHttp& admin_http_;
    std::unique_ptr<EventLoop::Handle> handle_;
    std::string request_;
    std::string response_;
    std::size_t response_offset_ = 0;
    bool closed_ = false;
};

void PruneClosedSessions(std::list<std::shared_ptr<RelaySession>>& sessions) {
    for (auto it = sessions.begin(); it != sessions.end();) {
        if (!*it || (*it)->closed()) {
            it = sessions.erase(it);
            continue;
        }
        ++it;
    }
}

template <typename T>
void PruneClosedConnections(std::list<std::shared_ptr<T>>& items) {
    for (auto it = items.begin(); it != items.end();) {
        if (!*it || (*it)->closed()) {
            it = items.erase(it);
            continue;
        }
        ++it;
    }
}

}  // namespace

void SetAdminSendHookForTesting(AdminSendHook hook) {
    AdminSendHookRef() = hook;
}

ssize_t DoAdminSend(int fd, const void* buffer, size_t length, int flags) {
    if (auto hook = AdminSendHookRef()) {
        return hook(fd, buffer, length, flags);
    }
    return ::send(fd, buffer, length, flags);
}

ProxyConfig ProxyConfig::FromEnv(std::initializer_list<EnvOverride> env) {
    ProxyConfig cfg;
    ApplyEnvOverrides(cfg, env);
    return cfg;
}

ProxyConfig ProxyConfig::FromArgs(int argc, char** argv) {
    ProxyConfig cfg;
    const CliParseResult cli = ParseCliOverrides(cfg, argc, argv);
    ApplyProcessEnvOverrides(cfg, cli);
    return cfg;
}

int RunProxyDaemon(const ProxyConfig& cfg) {
    ProxyState state;
    state.set_ready(false);

    InterfaceRegistry registry;
    auto admin_listener = CreatePlainListener("127.0.0.1", cfg.admin_port);
    if (!admin_listener) {
        std::cerr << "failed to create admin listener on port " << cfg.admin_port << '\n';
        return 1;
    }

    auto transparent_listener = CreateTransparentListener("0.0.0.0", cfg.transparent_port);
    if (!transparent_listener) {
        std::cerr << "failed to create transparent listener on port " << cfg.transparent_port << '\n';
        return 1;
    }

    const std::string admin_interface_name = "lan_listener_" + std::to_string(cfg.admin_port);
    const std::string transparent_interface_name = "wan_listener_" + std::to_string(cfg.transparent_port);
    registry.RecordInterface(admin_interface_name);
    registry.RecordInterface(transparent_interface_name);

    auto admin_http = BuildAdminHttp(state, registry);

    state.set_ready(true);
    auto& loop = state.loop();

    std::list<std::shared_ptr<RelaySession>> sessions;
    std::list<std::shared_ptr<AdminConnection>> admin_connections;

    std::function<void()> sweep;
    sweep = [&] {
        PruneClosedSessions(sessions);
        PruneClosedConnections(admin_connections);
        loop.Schedule(std::chrono::seconds(1), sweep);
    };
    loop.Schedule(std::chrono::seconds(1), sweep);

    auto admin_handle = loop.Register(
        admin_listener.fd_num(),
        true,
        false,
        [&] {
            while (true) {
                const int accepted_fd = ::accept(admin_listener.fd_num(), nullptr, nullptr);
                if (accepted_fd < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    break;
                }

                ScopedFd accepted(accepted_fd);
                if (!SetNonBlocking(accepted.get())) {
                    continue;
                }

                auto connection = std::make_shared<AdminConnection>(
                    loop, std::move(accepted), admin_http);
                connection->Arm();
                admin_connections.push_back(std::move(connection));
            }
        },
        {},
        {});

    auto transparent_handle = loop.Register(
        transparent_listener.fd(),
        true,
        false,
        [&] {
            while (true) {
                const int accepted_fd = ::accept(transparent_listener.fd(), nullptr, nullptr);
                if (accepted_fd < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    break;
                }

                ScopedFd accepted(accepted_fd);
                if (!SetNonBlocking(accepted.get())) {
                    continue;
                }

                SessionEndpoints endpoints{
                    .client = GetPeer(accepted.get()),
                    .original_dst = GetSockName(accepted.get()),
                };
                auto session = CreateRelaySession(
                    loop,
                    std::move(accepted),
                    endpoints,
                    [&loop, &sessions, &state, &registry] {
                        state.decrement_sessions();
                        registry.DecrementSessions();
                        loop.Defer([&sessions] { PruneClosedSessions(sessions); });
                    });
                if (!session) {
                    continue;
                }

                state.increment_sessions();
                registry.IncrementSessions();
                sessions.push_back(std::move(session));
            }
        },
        {},
        {});

    (void)admin_handle;
    (void)transparent_handle;

    loop.Run();
    state.set_ready(false);
    registry.RemoveInterface(admin_interface_name);
    registry.RemoveInterface(transparent_interface_name);
    return 0;
}

}  // namespace inline_proxy
