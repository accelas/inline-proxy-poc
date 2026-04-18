#include "shared/scoped_fd.hpp"

#include <cerrno>
#include <unistd.h>

namespace inline_proxy {

bool CloseFd(int fd) noexcept {
    if (fd < 0) {
        return true;
    }

    while (::close(fd) == -1) {
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

ScopedFd::ScopedFd() noexcept : fd_(-1) {}

ScopedFd::ScopedFd(int fd) noexcept : fd_(fd) {}

ScopedFd::~ScopedFd() {
    reset();
}

ScopedFd::ScopedFd(ScopedFd&& other) noexcept : fd_(other.release()) {}

ScopedFd& ScopedFd::operator=(ScopedFd&& other) noexcept {
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

int ScopedFd::get() const noexcept {
    return fd_;
}

bool ScopedFd::valid() const noexcept {
    return fd_ >= 0;
}

ScopedFd::operator bool() const noexcept {
    return valid();
}

int ScopedFd::release() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return fd;
}

void ScopedFd::reset(int fd) noexcept {
    if (fd_ == fd) {
        return;
    }
    CloseFd(fd_);
    fd_ = fd;
}

}  // namespace inline_proxy
