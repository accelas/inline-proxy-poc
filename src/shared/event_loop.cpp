#include "shared/event_loop.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <condition_variable>
#include <fcntl.h>
#include <limits>
#include <poll.h>
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
    std::atomic<bool> want_read{false};
    std::atomic<bool> want_write{false};
    Callback on_read;
    Callback on_write;
    ErrorCallback on_error;
    std::atomic<bool> active{true};
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

    bool removed = false;
    {
        std::lock_guard lock(mutex);
        auto it = registrations.find(registration->fd);
        if (it != registrations.end() && it->second == registration) {
            if (it->second) {
                it->second->active.store(false, std::memory_order_release);
            }
            registrations.erase(it);
            removed = true;
        }
    }

    if (removed) {
        Wake();
    }
}

void EventLoop::State::Update(const std::shared_ptr<Registration>& registration,
                              bool want_read,
                              bool want_write) {
    if (!registration) {
        return;
    }

    bool updated = false;
    {
        std::lock_guard lock(mutex);
        auto it = registrations.find(registration->fd);
        if (it != registrations.end() && it->second == registration && it->second) {
            it->second->want_read.store(want_read, std::memory_order_release);
            it->second->want_write.store(want_write, std::memory_order_release);
            updated = true;
        }
    }

    if (updated) {
        Wake();
    }
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

    auto timer_heap_less = [](const Timer& lhs, const Timer& rhs) {
        if (lhs.due != rhs.due) {
            return lhs.due > rhs.due;
        }
        return lhs.id > rhs.id;
    };

    std::lock_guard lock(mutex);
    while (!timers.empty() && callbacks.size() < kMaxDrainCallbacks) {
        if (timers.front().due > now) {
            break;
        }
        std::pop_heap(timers.begin(), timers.end(), timer_heap_less);
        auto timer = std::move(timers.back());
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
    if (delta.count() > static_cast<std::chrono::milliseconds::rep>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }
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
    auto state = state_;
    if (!state) {
        return;
    }

    const bool self_destruct = IsInEventLoopThread();
    Stop();

    if (!self_destruct) {
        {
            std::unique_lock lock(state->mutex);
            state->run_cv.wait(lock, [&state] { return !state->run_active; });
        }
    }

    state->alive.store(false, std::memory_order_release);
    state_.reset();
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
            it->second->active.store(false, std::memory_order_release);
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
        auto timer_heap_less = [](const Timer& lhs, const Timer& rhs) {
            if (lhs.due != rhs.due) {
                return lhs.due > rhs.due;
            }
            return lhs.id > rhs.id;
        };
        std::push_heap(state_->timers.begin(), state_->timers.end(), timer_heap_less);
    }
    state_->Wake();
}

void EventLoop::Run() {
    auto state = state_;
    if (!state) {
        return;
    }

    {
        std::lock_guard lock(state->mutex);
        if (state->stop_requested.load(std::memory_order_acquire)) {
            return;
        }
        state->loop_thread = std::this_thread::get_id();
        state->run_active = true;
    }

    struct RunReset {
        std::shared_ptr<State> state;
        ~RunReset() {
            {
                std::lock_guard lock(state->mutex);
                state->run_active = false;
                state->loop_thread = std::thread::id{};
            }
            state->run_cv.notify_all();
        }
    } reset{state};

    while (!state->stop_requested.load(std::memory_order_acquire)) {
        for (auto callback : state->TakeDeferred()) {
            if (!callback) {
                continue;
            }
            callback();
            if (state->stop_requested.load(std::memory_order_acquire)) {
                break;
            }
        }

        if (state->stop_requested.load(std::memory_order_acquire)) {
            break;
        }

        for (auto callback : state->TakeDueTimers()) {
            if (!callback) {
                continue;
            }
            callback();
            if (state->stop_requested.load(std::memory_order_acquire)) {
                break;
            }
        }

        if (state->stop_requested.load(std::memory_order_acquire)) {
            break;
        }

        std::vector<std::shared_ptr<Registration>> registrations;
        {
            std::lock_guard lock(state->mutex);
            registrations.reserve(state->registrations.size());
            for (const auto& entry : state->registrations) {
                if (entry.second && entry.second->active.load(std::memory_order_acquire)) {
                    registrations.push_back(entry.second);
                }
            }
        }

        std::vector<pollfd> pollfds;
        pollfds.reserve(registrations.size() + 1);
        pollfds.push_back(pollfd{.fd = state->wakeup_read_fd, .events = POLLIN, .revents = 0});
        for (const auto& registration : registrations) {
            short events = 0;
            if (registration->want_read.load(std::memory_order_acquire)) {
                events |= POLLIN;
            }
            if (registration->want_write.load(std::memory_order_acquire)) {
                events |= POLLOUT;
            }
            pollfds.push_back(pollfd{.fd = registration->fd, .events = events, .revents = 0});
        }

        const int timeout_ms = state->ComputeTimeoutMillis();
        const int rc = ::poll(pollfds.data(), static_cast<nfds_t>(pollfds.size()), timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "poll");
        }

        if (pollfds[0].revents != 0) {
            state->DrainWakeup();
        }

        if (state->stop_requested.load(std::memory_order_acquire)) {
            continue;
        }

        for (std::size_t i = 0; i < registrations.size(); ++i) {
            const auto& registration = registrations[i];
            if (!registration || !registration->active.load(std::memory_order_acquire)) {
                continue;
            }

            const short revents = pollfds[i + 1].revents;
            if (revents == 0) {
                continue;
            }

            const bool terminal = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
            bool should_stop = false;

            if ((revents & POLLIN) != 0 &&
                registration->want_read.load(std::memory_order_acquire) &&
                registration->on_read) {
                registration->on_read();
                should_stop = state->stop_requested.load(std::memory_order_acquire);
            }

            if (!should_stop &&
                registration->active.load(std::memory_order_acquire) &&
                (revents & POLLOUT) != 0 &&
                registration->want_write.load(std::memory_order_acquire) &&
                registration->on_write) {
                registration->on_write();
                should_stop = state->stop_requested.load(std::memory_order_acquire);
            }

            if (!should_stop &&
                registration->active.load(std::memory_order_acquire) &&
                terminal &&
                registration->on_error) {
                registration->on_error(revents);
                should_stop = state->stop_requested.load(std::memory_order_acquire);
            }

            if (terminal && registration->active.load(std::memory_order_acquire)) {
                state->Remove(registration);
            }

            if (should_stop) {
                break;
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
