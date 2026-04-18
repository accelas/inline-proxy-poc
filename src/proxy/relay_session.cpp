#include "proxy/relay_session.hpp"

#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

namespace inline_proxy {
namespace {

constexpr std::size_t kBufferSize = 16 * 1024;

}  // namespace

RelaySession::RelaySession(EventLoop& loop, ScopedFd client_fd, ScopedFd upstream_fd)
    : loop_(&loop), client_fd_(std::move(client_fd)), upstream_fd_(std::move(upstream_fd)) {}

RelaySession::~RelaySession() {
    Close();
}

std::shared_ptr<RelaySession> RelaySession::Create(EventLoop& loop,
                                                   ScopedFd client_fd,
                                                   const SessionEndpoints& endpoints) {
    if (!client_fd) {
        return {};
    }

    if (!SetNonBlocking(client_fd.get())) {
        return {};
    }

    auto upstream_fd = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
    if (!upstream_fd) {
        return {};
    }

    auto session = std::shared_ptr<RelaySession>(new RelaySession(loop, std::move(client_fd), std::move(upstream_fd)));
    session->Arm();
    session->UpdateInterest();
    return session;
}

void RelaySession::Arm() {
    auto weak = weak_from_this();
    client_handle_ = loop_->Register(
        client_fd_.get(),
        true,
        false,
        [weak] {
            if (auto self = weak.lock()) {
                self->OnClientReadable();
            }
        },
        [weak] {
            if (auto self = weak.lock()) {
                self->OnClientWritable();
            }
        },
        [weak](int) {
            if (auto self = weak.lock()) {
                self->Close();
            }
        });

    upstream_handle_ = loop_->Register(
        upstream_fd_.get(),
        true,
        false,
        [weak] {
            if (auto self = weak.lock()) {
                self->OnUpstreamReadable();
            }
        },
        [weak] {
            if (auto self = weak.lock()) {
                self->OnUpstreamWritable();
            }
        },
        [weak](int) {
            if (auto self = weak.lock()) {
                self->Close();
            }
        });
}

void RelaySession::OnClientReadable() {
    if (!PumpRead(client_fd_.get(), client_to_upstream_, client_closed_)) {
        Close();
        return;
    }
    UpdateInterest();
}

void RelaySession::OnClientWritable() {
    if (!PumpWrite(client_fd_.get(), upstream_to_client_, upstream_to_client_offset_)) {
        Close();
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamReadable() {
    if (!PumpRead(upstream_fd_.get(), upstream_to_client_, upstream_closed_)) {
        Close();
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamWritable() {
    if (!PumpWrite(upstream_fd_.get(), client_to_upstream_, client_to_upstream_offset_)) {
        Close();
        return;
    }
    UpdateInterest();
}

bool RelaySession::PumpRead(int fd, std::string& buffer, bool& peer_closed) {
    char chunk[kBufferSize];
    while (true) {
        const ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            buffer.append(chunk, chunk + n);
            continue;
        }
        if (n == 0) {
            peer_closed = true;
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }
}

bool RelaySession::PumpWrite(int fd, std::string& buffer, std::size_t& offset) {
    while (offset < buffer.size()) {
        const ssize_t n = ::write(fd, buffer.data() + offset, buffer.size() - offset);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }
        return false;
    }

    if (offset >= buffer.size()) {
        buffer.clear();
        offset = 0;
    }
    return true;
}

void RelaySession::UpdateInterest() {
    if (closed_) {
        return;
    }

    if (client_handle_) {
        client_handle_->Update(!client_closed_, !upstream_to_client_.empty());
    }
    if (upstream_handle_) {
        upstream_handle_->Update(!upstream_closed_, !client_to_upstream_.empty());
    }
}

void RelaySession::Close() {
    if (closed_) {
        return;
    }
    closed_ = true;
    if (client_handle_) {
        client_handle_.reset();
    }
    if (upstream_handle_) {
        upstream_handle_.reset();
    }
    client_fd_.reset();
    upstream_fd_.reset();
}

std::shared_ptr<RelaySession> CreateRelaySession(EventLoop& loop,
                                                 ScopedFd client_fd,
                                                 const SessionEndpoints& endpoints) {
    return RelaySession::Create(loop, std::move(client_fd), endpoints);
}

}  // namespace inline_proxy
