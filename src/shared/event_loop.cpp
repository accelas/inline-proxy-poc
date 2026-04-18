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

EventLoop::Handle::Handle(EventLoop& loop, std::shared_ptr<Registration> registration)
    : loop_(&loop), registration_(std::move(registration)) {}

EventLoop::Handle::~Handle() {
    if (loop_ && registration_) {
        loop_->Remove(registration_);
    }
}

void EventLoop::Handle::Update(bool want_read, bool want_write) {
    if (loop_ && registration_) {
        loop_->Update(registration_, want_read, want_write);
    }
}

int EventLoop::Handle::fd() const noexcept {
    return registration_ ? registration_->fd : -1;
}

EventLoop::EventLoop() {
    int fds[2] = {-1, -1};
    if (!MakePipe(fds)) {
        throw std::system_error(errno, std::generic_category(), "pipe2");
    }
    wakeup_read_fd_ = fds[0];
    wakeup_write_fd_ = fds[1];
}

EventLoop::~EventLoop() {
    Stop();
    if (wakeup_read_fd_ >= 0) {
        ::close(wakeup_read_fd_);
    }
    if (wakeup_write_fd_ >= 0) {
        ::close(wakeup_write_fd_);
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
        std::lock_guard lock(mutex_);
        auto it = registrations_.find(fd);
        if (it != registrations_.end() && it->second) {
            it->second->active = false;
        }
        registrations_[fd] = registration;
    }
    Wake();
    return std::unique_ptr<Handle>(new Handle(*this, std::move(registration)));
}

void EventLoop::Defer(Callback fn) {
    {
        std::lock_guard lock(mutex_);
        deferred_.push_back(std::move(fn));
    }
    Wake();
}

void EventLoop::Schedule(std::chrono::milliseconds delay, Callback fn) {
    {
        std::lock_guard lock(mutex_);
        timers_.push_back(Timer{
            .due = std::chrono::steady_clock::now() + delay,
            .id = next_timer_id_++,
            .callback = std::move(fn),
        });
    }
    Wake();
}

void EventLoop::Run() {
    {
        std::lock_guard lock(mutex_);
        if (stop_requested_.load(std::memory_order_acquire)) {
            return;
        }
        loop_thread_ = std::this_thread::get_id();
    }

    while (!stop_requested_.load(std::memory_order_acquire)) {
        for (auto callback : TakeDeferred()) {
            if (callback) {
                callback();
            }
        }

        for (auto callback : TakeDueTimers()) {
            if (callback) {
                callback();
            }
        }

        if (stop_requested_.load(std::memory_order_acquire)) {
            break;
        }

        std::vector<std::shared_ptr<Registration>> registrations;
        {
            std::lock_guard lock(mutex_);
            registrations.reserve(registrations_.size());
            for (const auto& entry : registrations_) {
                if (entry.second && entry.second->active) {
                    registrations.push_back(entry.second);
                }
            }
        }

        std::vector<pollfd> pollfds;
        pollfds.reserve(registrations.size() + 1);
        pollfds.push_back(pollfd{.fd = wakeup_read_fd_, .events = POLLIN, .revents = 0});
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

        const int timeout_ms = ComputeTimeoutMillis();
        int rc = ::poll(pollfds.data(), static_cast<nfds_t>(pollfds.size()), timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "poll");
        }

        if (pollfds[0].revents != 0) {
            DrainWakeup();
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

            if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (registration->on_error) {
                    registration->on_error(revents);
                }
                continue;
            }

            if ((revents & POLLIN) && registration->want_read && registration->on_read) {
                registration->on_read();
            }
            if (!registration->active) {
                continue;
            }
            if ((revents & POLLOUT) && registration->want_write && registration->on_write) {
                registration->on_write();
            }
        }
    }
}

void EventLoop::Stop() {
    stop_requested_.store(true, std::memory_order_release);
    Wake();
}

bool EventLoop::IsInEventLoopThread() const noexcept {
    std::lock_guard lock(mutex_);
    return loop_thread_ == std::this_thread::get_id();
}

void EventLoop::Remove(const std::shared_ptr<Registration>& registration) {
    if (!registration) {
        return;
    }

    {
        std::lock_guard lock(mutex_);
        auto it = registrations_.find(registration->fd);
        if (it != registrations_.end() && it->second == registration) {
            if (it->second) {
                it->second->active = false;
            }
            registrations_.erase(it);
        }
    }
    Wake();
}

void EventLoop::Update(const std::shared_ptr<Registration>& registration,
                       bool want_read,
                       bool want_write) {
    if (!registration) {
        return;
    }

    std::lock_guard lock(mutex_);
    auto it = registrations_.find(registration->fd);
    if (it == registrations_.end() || it->second != registration || !it->second) {
        return;
    }
    it->second->want_read = want_read;
    it->second->want_write = want_write;
    Wake();
}

void EventLoop::Wake() {
    if (wakeup_write_fd_ < 0) {
        return;
    }
    const std::uint8_t byte = 1;
    while (true) {
        const ssize_t written = ::write(wakeup_write_fd_, &byte, sizeof(byte));
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

void EventLoop::DrainWakeup() {
    if (wakeup_read_fd_ < 0) {
        return;
    }
    std::uint8_t buffer[64];
    while (true) {
        const ssize_t read_bytes = ::read(wakeup_read_fd_, buffer, sizeof(buffer));
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

std::vector<EventLoop::Callback> EventLoop::TakeDeferred() {
    std::vector<Callback> callbacks;
    {
        std::lock_guard lock(mutex_);
        callbacks.reserve(std::min<std::size_t>(deferred_.size(), kMaxDrainCallbacks));
        while (!deferred_.empty() && callbacks.size() < kMaxDrainCallbacks) {
            callbacks.push_back(std::move(deferred_.front()));
            deferred_.pop_front();
        }
    }
    return callbacks;
}

std::vector<EventLoop::Callback> EventLoop::TakeDueTimers() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<Callback> callbacks;

    std::lock_guard lock(mutex_);
    auto it = timers_.begin();
    while (it != timers_.end() && callbacks.size() < kMaxDrainCallbacks) {
        if (it->due > now) {
            ++it;
            continue;
        }
        if (it->callback) {
            callbacks.push_back(std::move(it->callback));
        }
        it = timers_.erase(it);
    }

    return callbacks;
}

int EventLoop::ComputeTimeoutMillis() const {
    std::lock_guard lock(mutex_);
    if (!deferred_.empty()) {
        return 0;
    }
    if (timers_.empty()) {
        return -1;
    }

    auto earliest = std::min_element(timers_.begin(), timers_.end(), [](const Timer& lhs, const Timer& rhs) {
        if (lhs.due != rhs.due) {
            return lhs.due < rhs.due;
        }
        return lhs.id < rhs.id;
    });
    const auto now = std::chrono::steady_clock::now();
    if (earliest->due <= now) {
        return 0;
    }
    const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(earliest->due - now);
    return static_cast<int>(std::max<std::chrono::milliseconds::rep>(0, delta.count()));
}

}  // namespace inline_proxy
