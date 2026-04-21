#pragma once

#include <cstddef>
#include <memory>
#include <functional>
#include <string>
#include <sys/socket.h>

#include "proxy/local_source.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/scoped_fd.hpp"

namespace inline_proxy {

using SendHook = ssize_t (*)(int fd, const void* buffer, size_t length, int flags);
using ShutdownHook = int (*)(int fd, int how);
using CloseCallback = std::function<void()>;

struct SessionEndpoints {
    sockaddr_storage client{};
    sockaddr_storage original_dst{};
};

void SetSendHookForTesting(SendHook hook);
void SetShutdownHookForTesting(ShutdownHook hook);
std::size_t RelaySessionBufferHighWaterMark() noexcept;

class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    ~RelaySession();

    bool closed() const noexcept;

    static std::shared_ptr<RelaySession> Create(EventLoop& loop,
                                                ScopedFd client_fd,
                                                const SessionEndpoints& endpoints,
                                                CloseCallback on_close = {});

private:
    RelaySession(EventLoop& loop, ScopedFd client_fd, ScopedFd upstream_fd);

    void Arm();
    void OnClientReadable();
    void OnClientWritable();
    void OnUpstreamReadable();
    void OnUpstreamWritable();
    bool CompleteUpstreamConnect();
    bool MaybePropagateHalfClose();
    bool MaybeFinish();
    void Close();
    void UpdateInterest();

    bool PumpRead(int fd, std::string& buffer, std::size_t offset, bool& peer_closed);
    bool PumpWrite(int fd, std::string& buffer, std::size_t& offset);

    EventLoop* loop_ = nullptr;
    ScopedFd client_fd_;
    ScopedFd upstream_fd_;
    std::unique_ptr<EventLoop::Handle> client_handle_;
    std::unique_ptr<EventLoop::Handle> upstream_handle_;
    std::string client_to_upstream_;
    std::string upstream_to_client_;
    std::size_t client_to_upstream_offset_ = 0;
    std::size_t upstream_to_client_offset_ = 0;
    bool client_closed_ = false;
    bool upstream_closed_ = false;
    bool upstream_connecting_ = false;
    bool client_write_shutdown_ = false;
    bool upstream_write_shutdown_ = false;
    bool owns_local_source_ = false;
    sockaddr_storage local_source_{};
    bool closed_ = false;
    CloseCallback on_close_;
};

std::shared_ptr<RelaySession> CreateRelaySession(EventLoop& loop,
                                                 ScopedFd client_fd,
                                                 const SessionEndpoints& endpoints,
                                                 CloseCallback on_close = {});

}  // namespace inline_proxy
