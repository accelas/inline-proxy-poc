#include <chrono>
#include <future>
#include <thread>
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
