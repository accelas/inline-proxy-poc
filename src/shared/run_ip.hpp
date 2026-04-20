#pragma once

#include <string>
#include <vector>

namespace inline_proxy {

// Run `/usr/bin/ip <args>` via fork+execv in the current netns.
// Returns true iff the child exited with status 0. Used by the proxy
// daemon (for its transparent routing rule) and the CNI plugin (for
// splice-time route / rule manipulation). Empty args returns false
// immediately without forking.
bool RunIp(const std::vector<std::string>& args);

}  // namespace inline_proxy
