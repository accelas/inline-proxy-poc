#pragma once

namespace inline_proxy {

class ScopedFd {
public:
    ScopedFd() noexcept;
    explicit ScopedFd(int fd) noexcept;
    ~ScopedFd();

    ScopedFd(ScopedFd&& other) noexcept;
    ScopedFd& operator=(ScopedFd&& other) noexcept;

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const noexcept;
    bool valid() const noexcept;
    explicit operator bool() const noexcept;

    int release() noexcept;
    void reset(int fd = -1) noexcept;

private:
    int fd_;
};

bool CloseFd(int fd) noexcept;
using CloseHook = int (*)(int);
void SetCloseHookForTesting(CloseHook hook);

}  // namespace inline_proxy
