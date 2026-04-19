#include <cerrno>
#include <gtest/gtest.h>

#include "shared/scoped_fd.hpp"

namespace {

int g_close_calls = 0;

int FakeClose(int) {
    ++g_close_calls;
    errno = EINTR;
    return -1;
}

}  // namespace

TEST(ScopedFdCloseTest, DoesNotRetryCloseOnEintr) {
    g_close_calls = 0;
    inline_proxy::SetCloseHookForTesting(FakeClose);

    EXPECT_FALSE(inline_proxy::CloseFd(123));
    EXPECT_EQ(g_close_calls, 1);

    inline_proxy::SetCloseHookForTesting(nullptr);
}
