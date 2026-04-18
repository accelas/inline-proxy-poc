#include <atomic>
#include <chrono>
#include <future>
#include <limits>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>

#include <gtest/gtest.h>

#include "shared/event_loop.hpp"
#include "shared/scoped_fd.hpp"

TEST(EventLoopTest, StaleHandleDoesNotModifyOrRemoveReplacementRegistration) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    inline_proxy::ScopedFd read_fd(fds[0]);
    inline_proxy::ScopedFd write_fd(fds[1]);

    int stale_hits = 0;
    int live_hits = 0;

    auto stale = loop.Register(read_fd.get(), true, false,
                               [&] { ++stale_hits; },
                               {},
                               {});
    auto live = loop.Register(read_fd.get(), true, false,
                              [&] {
                                  ++live_hits;
                                  loop.Stop();
                              },
                              {},
                              {});

    stale->Update(false, false);
    stale.reset();

    const char byte = 'x';
    ASSERT_EQ(::write(write_fd.get(), &byte, 1), 1);

    std::packaged_task<void()> task([&] { loop.Run(); });
    auto future = task.get_future();
    std::thread runner(std::move(task));

    const auto status = future.wait_for(std::chrono::seconds(1));
    if (status != std::future_status::ready) {
        loop.Stop();
    }
    runner.join();

    EXPECT_EQ(status, std::future_status::ready)
        << "run loop did not stop after live registration fired";
    EXPECT_EQ(stale_hits, 0);
    EXPECT_EQ(live_hits, 1);
    (void)live;
}

TEST(EventLoopTest, EarlyStopIsHonoredBeforeRunStarts) {
    inline_proxy::EventLoop loop;
    loop.Stop();

    std::packaged_task<void()> task([&] { loop.Run(); });
    auto future = task.get_future();
    std::thread runner(std::move(task));

    const auto status = future.wait_for(std::chrono::seconds(1));
    if (status != std::future_status::ready) {
        loop.Stop();
    }
    runner.join();

    EXPECT_EQ(status, std::future_status::ready)
        << "run loop ignored a pre-start stop request";
}


TEST(EventLoopTest, ReadCallbackStillRunsWhenHangupArrivesWithBufferedData) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    inline_proxy::ScopedFd read_fd(fds[0]);
    inline_proxy::ScopedFd write_fd(fds[1]);

    std::promise<void> read_seen;
    std::string bytes;

    auto handle = loop.Register(read_fd.get(), true, false,
                                [&] {
                                    char buffer[16] = {};
                                    const ssize_t n = ::read(read_fd.get(), buffer, sizeof(buffer));
                                    if (n > 0) {
                                        bytes.append(buffer, buffer + n);
                                        read_seen.set_value();
                                        loop.Stop();
                                    }
                                },
                                {},
                                {});

    const char payload[] = {'h', 'i'};
    ASSERT_EQ(::write(write_fd.get(), payload, sizeof(payload)), static_cast<ssize_t>(sizeof(payload)));
    write_fd.reset();

    auto future = read_seen.get_future();
    std::thread runner([&] { loop.Run(); });
    ASSERT_EQ(future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "read callback did not run when POLLHUP arrived with POLLIN";
    runner.join();

    EXPECT_EQ(bytes, "hi");
    (void)handle;
}

TEST(EventLoopTest, TerminalReadCallbackWithoutErrorDoesNotSpin) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    inline_proxy::ScopedFd read_fd(fds[0]);
    inline_proxy::ScopedFd write_fd(fds[1]);

    std::promise<void> first_read_seen;
    auto first_read_future = first_read_seen.get_future();
    std::atomic<int> read_hits{0};

    auto handle = loop.Register(read_fd.get(), true, false,
                                [&] {
                                    const int hits = read_hits.fetch_add(1, std::memory_order_relaxed) + 1;
                                    char buffer[16] = {};
                                    const ssize_t n = ::read(read_fd.get(), buffer, sizeof(buffer));
                                    (void)n;
                                    if (hits == 1) {
                                        first_read_seen.set_value();
                                    }
                                },
                                {},
                                {});

    const char payload[] = {'h', 'i'};
    ASSERT_EQ(::write(write_fd.get(), payload, sizeof(payload)), static_cast<ssize_t>(sizeof(payload)));
    write_fd.reset();

    std::thread runner([&] { loop.Run(); });
    ASSERT_EQ(first_read_future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "initial read callback did not run";

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(read_hits.load(std::memory_order_relaxed), 1)
        << "terminal registration kept spinning after final read";

    loop.Stop();
    runner.join();
    (void)handle;
}

TEST(EventLoopTest, StopBeforeDispatchSkipsOtherReadyFdsAfterWakeupDrain) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    inline_proxy::ScopedFd read_fd(fds[0]);
    inline_proxy::ScopedFd write_fd(fds[1]);

    std::atomic<int> read_hits{0};
    std::promise<void> stop_requested;
    auto stop_requested_future = stop_requested.get_future();

    auto handle = loop.Register(read_fd.get(), true, false,
                                [&] {
                                    ++read_hits;
                                    char buffer[16] = {};
                                    const ssize_t n = ::read(read_fd.get(), buffer, sizeof(buffer));
                                    (void)n;
                                },
                                {},
                                {});

    std::thread runner([&] { loop.Run(); });

    std::thread stopper([&] {
        const char payload[] = {'o', 'k'};
        ASSERT_EQ(::write(write_fd.get(), payload, sizeof(payload)), static_cast<ssize_t>(sizeof(payload)));
        stop_requested.set_value();
        loop.Stop();
        for (int i = 0; i < 2000; ++i) {
            handle->Update(true, false);
        }
    });

    ASSERT_EQ(stop_requested_future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "stop thread did not reach loop.Stop()";
    stopper.join();
    runner.join();

    EXPECT_EQ(read_hits.load(std::memory_order_relaxed), 0)
        << "ready fd was dispatched after stop had already been requested";
    (void)handle;
}

TEST(EventLoopTest, DestructorDoesNotSelfDeadlockOnEventLoopThread) {
    std::promise<void> deleted;
    auto deleted_future = deleted.get_future();
    std::thread runner([&] {
        auto* loop = new inline_proxy::EventLoop();
        int fds[2];
        ASSERT_EQ(::pipe(fds), 0);
        inline_proxy::ScopedFd read_fd(fds[0]);
        inline_proxy::ScopedFd write_fd(fds[1]);

        auto handle = loop->Register(read_fd.get(), true, false,
                                     [&, loop] {
                                         char buffer[16] = {};
                                         const ssize_t n = ::read(read_fd.get(), buffer, sizeof(buffer));
                                         (void)n;
                                         delete loop;
                                         deleted.set_value();
                                     },
                                     {},
                                     {});

        const char payload[] = {'x'};
        ASSERT_EQ(::write(write_fd.get(), payload, sizeof(payload)), static_cast<ssize_t>(sizeof(payload)));
        loop->Run();
        (void)handle;
    });

    ASSERT_EQ(deleted_future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "event-loop-thread destructor deadlocked";
    runner.join();
}


TEST(EventLoopTest, DestructorWaitsForInFlightRunToExit) {
    auto* loop = new inline_proxy::EventLoop();

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    inline_proxy::ScopedFd read_fd(fds[0]);
    inline_proxy::ScopedFd write_fd(fds[1]);

    std::promise<void> callback_entered;
    auto callback_entered_future = callback_entered.get_future();
    std::promise<void> release_callback;
    auto release_callback_future = release_callback.get_future().share();

    auto handle = loop->Register(read_fd.get(), true, false,
                                 [&] {
                                     char buffer[1];
                                     (void)::read(read_fd.get(), buffer, sizeof(buffer));
                                     callback_entered.set_value();
                                     release_callback_future.wait();
                                 },
                                 {},
                                 {});

    const char byte = 'x';
    ASSERT_EQ(::write(write_fd.get(), &byte, 1), 1);

    std::thread runner([&] { loop->Run(); });
    ASSERT_EQ(callback_entered_future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "event loop callback did not start";

    std::promise<void> delete_done;
    auto delete_done_future = delete_done.get_future();
    std::thread deleter([&] {
        delete loop;
        delete_done.set_value();
    });

    EXPECT_EQ(delete_done_future.wait_for(std::chrono::milliseconds(50)), std::future_status::timeout)
        << "destructor returned before the in-flight Run() exited";

    release_callback.set_value();

    ASSERT_EQ(delete_done_future.wait_for(std::chrono::seconds(1)), std::future_status::ready)
        << "destructor did not finish after the callback was released";

    deleter.join();
    runner.join();
    (void)handle;
}


TEST(EventLoopTest, LoopThreadIdentityClearsAfterRunReturns) {
    inline_proxy::EventLoop loop;

    std::thread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        loop.Stop();
    });

    loop.Run();
    stopper.join();

    EXPECT_FALSE(loop.IsInEventLoopThread());
}


TEST(EventLoopTest, HandleOperationsAreSafeAfterLoopDestruction) {
    std::unique_ptr<inline_proxy::EventLoop::Handle> handle;

    {
        inline_proxy::EventLoop loop;
        int fds[2];
        ASSERT_EQ(::pipe(fds), 0);
        inline_proxy::ScopedFd read_fd(fds[0]);
        inline_proxy::ScopedFd write_fd(fds[1]);
        handle = loop.Register(read_fd.get(), true, false, {}, {}, {});
        EXPECT_GE(handle->fd(), 0);
        (void)write_fd;
    }

    ASSERT_NO_FATAL_FAILURE(handle->Update(false, false));
    handle.reset();
}

TEST(EventLoopTest, DueTimersRunInDeadlineOrder) {
    inline_proxy::EventLoop loop;
    std::vector<int> order;

    loop.Schedule(std::chrono::milliseconds(20), [&] { order.push_back(1); });
    loop.Schedule(std::chrono::milliseconds(1), [&] { order.push_back(2); });

    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    std::thread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        loop.Stop();
    });

    loop.Run();
    stopper.join();

    EXPECT_EQ(order, std::vector<int>({2, 1}));
}


TEST(EventLoopTest, DeferredCallbacksStopPreventsLaterDeferredCallbacks) {
    inline_proxy::EventLoop loop;
    std::vector<int> order;

    loop.Defer([&] {
        order.push_back(1);
        loop.Stop();
    });
    loop.Defer([&] { order.push_back(2); });

    loop.Run();

    EXPECT_EQ(order, std::vector<int>({1}));
}

TEST(EventLoopTest, TimerCallbacksStopPreventsLaterTimerCallbacks) {
    inline_proxy::EventLoop loop;
    std::vector<int> order;

    loop.Schedule(std::chrono::milliseconds(0), [&] {
        order.push_back(1);
        loop.Stop();
    });
    loop.Schedule(std::chrono::milliseconds(0), [&] { order.push_back(2); });

    loop.Run();

    EXPECT_EQ(order, std::vector<int>({1}));
}

TEST(EventLoopTest, PollCallbacksStopPreventsLaterPollCallbacksInSameCycle) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    inline_proxy::ScopedFd a(fds[0]);
    inline_proxy::ScopedFd b(fds[1]);

    std::vector<int> order;
    auto handle = loop.Register(a.get(), true, true,
                                [&] {
                                    char buffer[1];
                                    (void)::read(a.get(), buffer, sizeof(buffer));
                                    order.push_back(1);
                                    loop.Stop();
                                },
                                [&] { order.push_back(2); },
                                {});

    const char byte = 'x';
    ASSERT_EQ(::write(b.get(), &byte, 1), 1);

    loop.Run();

    EXPECT_EQ(order, std::vector<int>({1}));
    (void)handle;
}


TEST(EventLoopTest, PendingTimerIsNotDuplicatedByEarlyWakeups) {
    inline_proxy::EventLoop loop;
    std::vector<int> order;

    loop.Schedule(std::chrono::milliseconds(100), [&] { order.push_back(1); });
    loop.Schedule(std::chrono::milliseconds(250), [&] { loop.Stop(); });

    std::thread waker([&] {
        for (int i = 0; i < 10; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            loop.Defer([] {});
        }
    });

    loop.Run();
    waker.join();

    EXPECT_EQ(order, std::vector<int>({1}));
}

TEST(EventLoopTest, WriteCallbackIsSkippedAfterConcurrentUpdateDisablesIt) {
    inline_proxy::EventLoop loop;

    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    inline_proxy::ScopedFd a(fds[0]);
    inline_proxy::ScopedFd b(fds[1]);

    int read_hits = 0;
    int write_hits = 0;
    std::promise<void> read_entered;
    std::promise<void> update_done;
    auto read_entered_future = read_entered.get_future().share();
    auto update_done_future = update_done.get_future().share();
    std::unique_ptr<inline_proxy::EventLoop::Handle> handle;

    handle = loop.Register(a.get(), true, true,
                           [&] {
                               ++read_hits;
                               read_entered.set_value();
                               update_done_future.wait();
                               char buffer[1];
                               (void)::read(a.get(), buffer, sizeof(buffer));
                           },
                           [&] { ++write_hits; },
                           {});

    std::thread updater([&] {
        read_entered_future.wait();
        handle->Update(true, false);
        update_done.set_value();
    });

    const char byte = 'x';
    ASSERT_EQ(::write(b.get(), &byte, 1), 1);

    std::thread stopper([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        loop.Stop();
    });

    loop.Run();
    updater.join();
    stopper.join();

    EXPECT_EQ(read_hits, 1);
    EXPECT_EQ(write_hits, 0);
}
