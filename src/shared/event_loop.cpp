#include "shared/event_loop.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <poll.h>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace inline_proxy {
namespace {

constexpr std::size_t kMaxDrainCallbacks = 1024;

bool MakePipe(int fds[2]) {
#if defined(__linux__)
    return ::pipe2(fds, O_CLOEXEC | O_NONBLOCK) == 0;
#else
    if (::pipe(fds) != 0) {
        return false;
    }
    for (int fd : fds) {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            return false;
        }
        int cloexec = ::fcntl(fd, F_GETFD, 0);
        if (cloexec < 0 || ::fcntl(fd, F_SETFD, cloexec | FD_CLOEXEC) != 0) {
            return false;
        }
    }
    return true;
#endif
}

}  // namespace

struct EventLoop::Registration {
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
    Callback on_read;
    Callback on_write;
    ErrorCallback on_error;
    bool active = true;
};

struct EventLoop::Timer {
    std::chrono::steady_clock::time_point due;
    std::uint64_t id = 0;
    Callback callback;
};

EventLoop::State::~State() {
    if (wakeup_read_fd >= 0) {
        ::close(wakeup_read_fd);
    }
    if (wakeup_write_fd >= 0) {
        ::close(wakeup_write_fd);
    }
}

void EventLoop::State::Remove(const std::shared_ptr<Registration>& registration) {
    if (!registration) {
        return;
    }

    {
        std::lock_guard lock(mutex);
        auto it = registrations.find(registration->fd);
        if (it != registrations.end() && it->second == registration) {
            if (it->second) {
                it->second->active = false;
            }
            registrations.erase(it);
        }
    }
    Wake();
}

void EventLoop::State::Update(const std::shared_ptr<Registration>& registration,
                              bool want_read,
                              bool want_write) {
    if (!registration) {
        return;
    }

    std::lock_guard lock(mutex);
    auto it = registrations.find(registration->fd);
    if (it == registrations.end() || it->second != registration || !it->second) {
        return;
    }
    it->second->want_read = want_read;
    it->second->want_write = want_write;
    Wake();
}

void EventLoop::State::Wake() {
    if (!alive.load(std::memory_order_acquire) || wakeup_write_fd < 0) {
        return;
    }
    const std::uint8_t byte = 1;
    while (true) {
        const ssize_t written = ::write(wakeup_write_fd, &byte, sizeof(byte));
        if (written == static_cast<ssize_t>(sizeof(byte))) {
            return;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        return;
    }
}

void EventLoop::State::DrainWakeup() {
    if (wakeup_read_fd < 0) {
        return;
    }
    std::uint8_t buffer[64];
    while (true) {
        const ssize_t read_bytes = ::read(wakeup_read_fd, buffer, sizeof(buffer));
        if (read_bytes > 0) {
            continue;
        }
        if (read_bytes < 0 && errno == EINTR) {
            continue;
        }
        if (read_bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        return;
    }
}

std::vector<EventLoop::Callback> EventLoop::State::TakeDeferred() {
    std::vector<Callback> callbacks;
    {
        std::lock_guard lock(mutex);
        callbacks.reserve(std::min<std::size_t>(deferred.size(), kMaxDrainCallbacks));
        while (!deferred.empty() && callbacks.size() < kMaxDrainCallbacks) {
            callbacks.push_back(std::move(deferred.front()));
            deferred.pop_front();
        }
    }
    return callbacks;
}

std::vector<EventLoop::Callback> EventLoop::State::TakeDueTimers() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<Callback> callbacks;

    std::lock_guard lock(mutex);
    while (!timers.empty() && callbacks.size() < kMaxDrainCallbacks) {
        std::pop_heap(timers.begin(), timers.end(), [](const Timer& lhs, const Timer& rhs) {
            if (lhs.due != rhs.due) {
                return lhs.due > rhs.due;
            }
            return lhs.id > rhs.id;
        });
        auto timer = std::move(timers.back());
        if (timer.due > now) {
            timers.push_back(std::move(timer));
            std::push_heap(timers.begin(), timers.end(), [](const Timer& lhs, const Timer& rhs) {
                if (lhs.due != rhs.due) {
                    return lhs.due > rhs.due;
                }
                return lhs.id > rhs.id;
            });
            break;
        }
        timers.pop_back();
        if (timer.callback) {
            callbacks.push_back(std::move(timer.callback));
        }
    }

    return callbacks;
}

int EventLoop::State::ComputeTimeoutMillis() const {
    std::lock_guard lock(mutex);
    if (!deferred.empty()) {
        return 0;
    }
    if (timers.empty()) {
        return -1;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto& earliest = timers.front();
    if (earliest.due <= now) {
        return 0;
    }
    const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(earliest.due - now);
    return static_cast<int>(std::max<std::chrono::milliseconds::rep>(0, delta.count()));
}

EventLoop::Handle::Handle(std::shared_ptr<State> state,
                          std::shared_ptr<Registration> registration)
    : state_(std::move(state)), registration_(std::move(registration)) {}

EventLoop::Handle::~Handle() {
    if (state_ && registration_) {
        state_->Remove(registration_);
    }
}

void EventLoop::Handle::Update(bool want_read, bool want_write) {
    if (state_ && registration_) {
        state_->Update(registration_, want_read, want_write);
    }
}

int EventLoop::Handle::fd() const noexcept {
    return registration_ ? registration_->fd : -1;
}

EventLoop::EventLoop() : state_(std::make_shared<State>()) {
    int fds[2] = {-1, -1};
    if (!MakePipe(fds)) {
        throw std::system_error(errno, std::generic_category(), "pipe2");
    }
    state_->wakeup_read_fd = fds[0];
    state_->wakeup_write_fd = fds[1];
}

EventLoop::~EventLoop() {
    Stop();
    if (state_) {
        state_->alive.store(false, std::memory_order_release);
        state_.reset();
    }
}

std::unique_ptr<EventLoop::Handle> EventLoop::Register(
    int fd,
    bool want_read,
    bool want_write,
    Callback on_read,
    Callback on_write,
    ErrorCallback on_error) {
    auto registration = std::make_shared<Registration>();
    registration->fd = fd;
    registration->want_read = want_read;
    registration->want_write = want_write;
    registration->on_read = std::move(on_read);
    registration->on_write = std::move(on_write);
    registration->on_error = std::move(on_error);

    {
        std::lock_guard lock(state_->mutex);
        auto it = state_->registrations.find(fd);
        if (it != state_->registrations.end() && it->second) {
            it->second->active = false;
        }
        state_->registrations[fd] = registration;
    }
    state_->Wake();
    return std::unique_ptr<Handle>(new Handle(state_, std::move(registration)));
}

void EventLoop::Defer(Callback fn) {
    {
        std::lock_guard lock(state_->mutex);
        state_->deferred.push_back(std::move(fn));
    }
    state_->Wake();
}

void EventLoop::Schedule(std::chrono::milliseconds delay, Callback fn) {
    {
        std::lock_guard lock(state_->mutex);
        state_->timers.push_back(Timer{
            .due = std::chrono::steady_clock::now() + delay,
            .id = state_->next_timer_id++,
            .callback = std::move(fn),
        });
        std::push_heap(state_->timers.begin(), state_->timers.end(), [](const Timer& lhs, const Timer& rhs) {
            if (lhs.due != rhs.due) {
                return lhs.due > rhs.due;
            }
            return lhs.id > rhs.id;
        });
    }
    state_->Wake();
}

void EventLoop::Run() {
    {
        std::lock_guard lock(state_->mutex);
        if (state_->stop_requested.load(std::memory_order_acquire)) {
            return;
        }
        state_->loop_thread = std::this_thread::get_id();
    }

    struct LoopThreadReset {
        State& state;
        ~LoopThreadReset() {
            std::lock_guard lock(state.mutex);
            state.loop_thread = std::thread::id{};
        }
    } reset{*state_};

    while (!state_->stop_requested.load(std::memory_order_acquire)) {
        for (auto callback : state_->TakeDeferred()) {
            if (callback) {
                callback();
            }
        }

        for (auto callback : state_->TakeDueTimers()) {
            if (callback) {
                callback();
            }
        }

        if (state_->stop_requested.load(std::memory_order_acquire)) {
            break;
        }

        std::vector<std::shared_ptr<Registration>> registrations;
        {
            std::lock_guard lock(state_->mutex);
            registrations.reserve(state_->registrations.size());
            for (const auto& entry : state_->registrations) {
                if (entry.second && entry.second->active) {
                    registrations.push_back(entry.second);
                }
            }
        }

        std::vector<pollfd> pollfds;
        pollfds.reserve(registrations.size() + 1);
        pollfds.push_back(pollfd{.fd = state_->wakeup_read_fd, .events = POLLIN, .revents = 0});
        for (const auto& registration : registrations) {
            short events = 0;
            if (registration->want_read) {
                events |= POLLIN;
            }
            if (registration->want_write) {
                events |= POLLOUT;
            }
            pollfds.push_back(pollfd{.fd = registration->fd, .events = events, .revents = 0});
        }

        const int timeout_ms = state_->ComputeTimeoutMillis();
        int rc = ::poll(pollfds.data(), static_cast<nfds_t>(pollfds.size()), timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "poll");
        }

        if (pollfds[0].revents != 0) {
            state_->DrainWakeup();
        }

        for (std::size_t i = 0; i < registrations.size(); ++i) {
            const auto& registration = registrations[i];
            if (!registration || !registration->active) {
                continue;
            }

            const short revents = pollfds[i + 1].revents;
            if (revents == 0) {
                continue;
            }

            const bool want_read = registration->want_read && (revents & POLLIN);
            const bool want_write = registration->want_write && (revents & POLLOUT);
            const bool terminal = revents & (POLLERR | POLLHUP | POLLNVAL);

            if (want_read && registration->on_read) {
                registration->on_read();
            }
            if (!registration->active) {
                continue;
            }
            if (want_write && registration->on_write) {
                registration->on_write();
            }
            if (!registration->active) {
                continue;
            }
            if (terminal && registration->on_error) {
                registration->on_error(revents);
            }
            if (!registration->active) {
                continue;
            }
            if ((revents & POLLNVAL) != 0) {
                state_->Remove(registration);
            }
        }
    }
}

void EventLoop::Stop() {
    if (!state_) {
        return;
    }
    state_->stop_requested.store(true, std::memory_order_release);
    state_->Wake();
}

bool EventLoop::IsInEventLoopThread() const noexcept {
    if (!state_) {
        return false;
    }
    std::lock_guard lock(state_->mutex);
    return state_->loop_thread == std::this_thread::get_id();
}

}  // namespace inline_proxy
