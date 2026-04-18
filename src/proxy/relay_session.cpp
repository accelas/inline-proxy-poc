#include "proxy/relay_session.hpp"

#include <algorithm>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

namespace inline_proxy {
namespace {

constexpr std::size_t kReadChunkBytes = 16 * 1024;
constexpr std::size_t kMaxBufferedBytes = 128 * 1024;

SendHook& SendHookRef() {
    static SendHook hook = nullptr;
    return hook;
}

ShutdownHook& ShutdownHookRef() {
    static ShutdownHook hook = nullptr;
    return hook;
}

ssize_t DoSend(int fd, const void* buffer, size_t length, int flags) {
    if (auto hook = SendHookRef()) {
        return hook(fd, buffer, length, flags);
    }
    return ::send(fd, buffer, length, flags);
}

int DoShutdown(int fd, int how) {
    if (auto hook = ShutdownHookRef()) {
        return hook(fd, how);
    }
    return ::shutdown(fd, how);
}

std::size_t PendingBytes(const std::string& buffer, std::size_t offset) {
    return offset < buffer.size() ? buffer.size() - offset : 0;
}

void CompactBuffer(std::string& buffer, std::size_t& offset) {
    if (offset == 0) {
        return;
    }
    if (offset >= buffer.size()) {
        buffer.clear();
        offset = 0;
        return;
    }
    if (offset >= kReadChunkBytes || offset * 2 >= buffer.size()) {
        buffer.erase(0, offset);
        offset = 0;
    }
}

}  // namespace

void SetSendHookForTesting(SendHook hook) {
    SendHookRef() = hook;
}

void SetShutdownHookForTesting(ShutdownHook hook) {
    ShutdownHookRef() = hook;
}

std::size_t RelaySessionBufferHighWaterMark() noexcept {
    return kMaxBufferedBytes;
}

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

    auto upstream = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
    if (!upstream) {
        return {};
    }

    auto session = std::shared_ptr<RelaySession>(
        new RelaySession(loop, std::move(client_fd), std::move(upstream.fd)));
    session->upstream_connecting_ = upstream.connecting;
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
    if (!PumpRead(client_fd_.get(), client_to_upstream_, client_to_upstream_offset_, client_closed_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnClientWritable() {
    if (!PumpWrite(client_fd_.get(), upstream_to_client_, upstream_to_client_offset_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamReadable() {
    if (upstream_connecting_) {
        return;
    }
    if (!PumpRead(upstream_fd_.get(), upstream_to_client_, upstream_to_client_offset_, upstream_closed_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamWritable() {
    if (upstream_connecting_) {
        if (!CompleteUpstreamConnect()) {
            Close();
            return;
        }
    }
    if (!PumpWrite(upstream_fd_.get(), client_to_upstream_, client_to_upstream_offset_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

bool RelaySession::CompleteUpstreamConnect() {
    int socket_error = 0;
    socklen_t len = sizeof(socket_error);
    if (::getsockopt(upstream_fd_.get(), SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0) {
        return false;
    }
    if (socket_error != 0) {
        errno = socket_error;
        return false;
    }
    upstream_connecting_ = false;
    return true;
}

bool RelaySession::MaybePropagateHalfClose() {
    if (client_closed_ &&
        PendingBytes(client_to_upstream_, client_to_upstream_offset_) == 0 &&
        !upstream_connecting_ &&
        !upstream_write_shutdown_) {
        if (DoShutdown(upstream_fd_.get(), SHUT_WR) != 0) {
            return false;
        }
        upstream_write_shutdown_ = true;
    }

    if (upstream_closed_ &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) == 0 &&
        !client_write_shutdown_) {
        if (DoShutdown(client_fd_.get(), SHUT_WR) != 0) {
            return false;
        }
        client_write_shutdown_ = true;
    }

    return true;
}

bool RelaySession::MaybeFinish() {
    const bool client_to_upstream_done =
        client_closed_ &&
        PendingBytes(client_to_upstream_, client_to_upstream_offset_) == 0 &&
        upstream_write_shutdown_;
    const bool upstream_to_client_done =
        upstream_closed_ &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) == 0 &&
        client_write_shutdown_;

    if (client_to_upstream_done && upstream_to_client_done) {
        Close();
        return true;
    }
    return false;
}

bool RelaySession::PumpRead(int fd,
                            std::string& buffer,
                            std::size_t offset,
                            bool& peer_closed) {
    const std::size_t pending = PendingBytes(buffer, offset);
    if (pending >= kMaxBufferedBytes) {
        return true;
    }

    char chunk[kReadChunkBytes];
    while (true) {
        const std::size_t space_left = kMaxBufferedBytes - PendingBytes(buffer, offset);
        if (space_left == 0) {
            return true;
        }

        const ssize_t n = ::read(fd, chunk, std::min<std::size_t>(sizeof(chunk), space_left));
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
        const ssize_t n = DoSend(fd,
                                 buffer.data() + offset,
                                 buffer.size() - offset,
                                 MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            CompactBuffer(buffer, offset);
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

    buffer.clear();
    offset = 0;
    return true;
}

void RelaySession::UpdateInterest() {
    if (closed_) {
        return;
    }

    if (client_handle_) {
        client_handle_->Update(!client_closed_ &&
                                   PendingBytes(client_to_upstream_, client_to_upstream_offset_) < kMaxBufferedBytes,
                               PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0);
    }
    if (upstream_handle_) {
        upstream_handle_->Update(!upstream_closed_ &&
                                     !upstream_connecting_ &&
                                     PendingBytes(upstream_to_client_, upstream_to_client_offset_) < kMaxBufferedBytes,
                                 upstream_connecting_ ||
                                     PendingBytes(client_to_upstream_, client_to_upstream_offset_) > 0);
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
