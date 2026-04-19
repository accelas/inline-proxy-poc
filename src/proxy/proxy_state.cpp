#include "proxy/proxy_state.hpp"

#include <stdexcept>
#include <string>

namespace inline_proxy {

EventLoop& ProxyState::loop() noexcept {
    return loop_;
}

const EventLoop& ProxyState::loop() const noexcept {
    return loop_;
}

bool ProxyState::ready() const noexcept {
    return ready_;
}

void ProxyState::set_ready(bool ready) noexcept {
    ready_ = ready;
}

std::size_t ProxyState::active_sessions() const noexcept {
    return active_sessions_;
}

std::size_t ProxyState::total_connections() const noexcept {
    return total_connections_;
}

void ProxyState::increment_sessions() noexcept {
    ++active_sessions_;
    ++total_connections_;
}

void ProxyState::decrement_sessions() {
    if (active_sessions_ == 0) {
        throw std::logic_error("proxy session underflow");
    }
    --active_sessions_;
}

std::string ProxyState::MetricsText() const {
    std::string output;
    output += "# HELP inline_proxy_ready Proxy readiness flag\n";
    output += "# TYPE inline_proxy_ready gauge\n";
    output += "inline_proxy_ready ";
    output += ready_ ? '1' : '0';
    output += '\n';
    output += "# HELP inline_proxy_active_sessions Current active relay sessions\n";
    output += "# TYPE inline_proxy_active_sessions gauge\n";
    output += "inline_proxy_active_sessions ";
    output += std::to_string(active_sessions_);
    output += '\n';
    output += "# HELP inline_proxy_total_connections Total proxied connections accepted\n";
    output += "# TYPE inline_proxy_total_connections counter\n";
    output += "inline_proxy_total_connections ";
    output += std::to_string(total_connections_);
    output += '\n';
    return output;
}

std::string ProxyState::SessionsText() const {
    std::string output;
    output += "active_sessions=";
    output += std::to_string(active_sessions_);
    output += '\n';
    return output;
}

}  // namespace inline_proxy
