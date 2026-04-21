#pragma once

#include <sys/socket.h>

// Transparent-source support: when the proxy's upstream socket binds to the
// original client IP (the default transparent pattern), that IP must be
// locally assignable so outbound packets keep that source and return packets
// are delivered back to the proxy. This module adds/removes a /32 copy of
// the client IP on wan_* interfaces for the duration of a session.
//
// This whole file is optional. Deployments that run with
// `INLINE_PROXY_SKIP_LOCAL_SOURCE=1` or with `INLINE_PROXY_USE_PROXY_SOURCE=1`
// (i.e. proxy-source upstream connects, e.g. the routed k3s deployment)
// do not need it, and the entire file can be deleted once those modes
// become the only supported configuration.

namespace inline_proxy {

using AcquireLocalSourceHook = bool (*)(const sockaddr_storage&);
using ReleaseLocalSourceHook = void (*)(const sockaddr_storage&);

bool AcquireLocalSourceAddress(const sockaddr_storage& addr);
void ReleaseLocalSourceAddress(const sockaddr_storage& addr);

void SetAcquireLocalSourceHookForTesting(AcquireLocalSourceHook hook);
void SetReleaseLocalSourceHookForTesting(ReleaseLocalSourceHook hook);

}  // namespace inline_proxy
