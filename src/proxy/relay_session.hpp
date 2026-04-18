#pragma once

#include <cstddef>
#include <memory>
#include <string>

#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/scoped_fd.hpp"

namespace inline_proxy {

struct SessionEndpoints {
    sockaddr_storage client{};
    sockaddr_storage original_dst{};
};

class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    ~RelaySession();

    static std::shared_ptr<RelaySession> Create(EventLoop& loop,
                                                ScopedFd client_fd,
                                                const SessionEndpoints& endpoints);

private:
    RelaySession(EventLoop& loop, ScopedFd client_fd, ScopedFd upstream_fd);

    void Arm();
    void OnClientReadable();
    void OnClientWritable();
    void OnUpstreamReadable();
    void OnUpstreamWritable();
    void Close();
    void UpdateInterest();

    bool PumpRead(int fd, std::string& buffer, bool& peer_closed);
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
    bool closed_ = false;
};

std::shared_ptr<RelaySession> CreateRelaySession(EventLoop& loop,
                                                 ScopedFd client_fd,
                                                 const SessionEndpoints& endpoints);

}  // namespace inline_proxy
