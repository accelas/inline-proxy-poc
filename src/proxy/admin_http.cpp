#include "proxy/admin_http.hpp"

#include <utility>

namespace inline_proxy {
namespace {

AdminResponse MakeTextResponse(int status, std::string body) {
    return AdminResponse{
        .status = status,
        .content_type = "text/plain; charset=utf-8",
        .body = std::move(body),
    };
}

}  // namespace

AdminHttp::AdminHttp(ProxyState& state) noexcept : state_(&state) {}

AdminResponse AdminHttp::Handle(std::string_view method, std::string_view path) const {
    if (method != "GET") {
        return MakeTextResponse(405, "method not allowed\n");
    }

    if (path == "/healthz") {
        return MakeTextResponse(200, "ok\n");
    }
    if (path == "/readyz") {
        return state_ && state_->ready()
                   ? MakeTextResponse(200, "ready\n")
                   : MakeTextResponse(503, "not ready\n");
    }
    if (path == "/metrics") {
        return AdminResponse{
            .status = 200,
            .content_type = "text/plain; version=0.0.4; charset=utf-8",
            .body = state_ ? state_->MetricsText() : std::string(),
        };
    }
    if (path == "/sessions") {
        return AdminResponse{
            .status = 200,
            .content_type = "text/plain; charset=utf-8",
            .body = state_ ? state_->SessionsText() : std::string(),
        };
    }

    return MakeTextResponse(404, "not found\n");
}

AdminHttp BuildAdminHttp(ProxyState& state) noexcept {
    return AdminHttp(state);
}

}  // namespace inline_proxy
