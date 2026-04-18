#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace inline_proxy {

class EventLoop {
private:
    struct Registration;
    struct Timer;

public:
    using Callback = std::function<void()>;
    using ErrorCallback = std::function<void(int)>;

    class Handle {
    public:
        ~Handle();

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        void Update(bool want_read, bool want_write);
        int fd() const noexcept;

    private:
        friend class EventLoop;

        Handle(EventLoop& loop, std::shared_ptr<Registration> registration);

        EventLoop* loop_;
        std::shared_ptr<Registration> registration_;
    };

    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    std::unique_ptr<Handle> Register(int fd,
                                     bool want_read,
                                     bool want_write,
                                     Callback on_read,
                                     Callback on_write,
                                     ErrorCallback on_error);

    void Defer(Callback fn);
    void Schedule(std::chrono::milliseconds delay, Callback fn);
    void Run();
    void Stop();
    bool IsInEventLoopThread() const noexcept;

private:
    void Remove(const std::shared_ptr<Registration>& registration);
    void Update(const std::shared_ptr<Registration>& registration,
                bool want_read,
                bool want_write);
    void Wake();
    void DrainWakeup();
    std::vector<Callback> TakeDeferred();
    std::vector<Callback> TakeDueTimers();
    int ComputeTimeoutMillis() const;

    int wakeup_read_fd_ = -1;
    int wakeup_write_fd_ = -1;
    mutable std::mutex mutex_;
    std::unordered_map<int, std::shared_ptr<Registration>> registrations_;
    std::deque<Callback> deferred_;
    std::vector<Timer> timers_;
    std::uint64_t next_timer_id_ = 0;
    std::atomic<bool> stop_requested_{false};
    std::thread::id loop_thread_;
};

}  // namespace inline_proxy
