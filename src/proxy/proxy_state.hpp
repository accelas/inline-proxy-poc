#pragma once

#include <cstddef>
#include <string>

#include "shared/event_loop.hpp"

namespace inline_proxy {

class ProxyState {
public:
    ProxyState() = default;

    EventLoop& loop() noexcept;
    const EventLoop& loop() const noexcept;

    bool ready() const noexcept;
    void set_ready(bool ready) noexcept;

    std::size_t active_sessions() const noexcept;
    void increment_sessions() noexcept;
    void decrement_sessions();

    std::string MetricsText() const;
    std::string SessionsText() const;

private:
    EventLoop loop_;
    bool ready_ = true;
    std::size_t active_sessions_ = 0;
};

}  // namespace inline_proxy
