#pragma once

#include <optional>
#include <string_view>

#include "cni/cni_types.hpp"

namespace inline_proxy {

std::optional<PrevResult> ParsePrevResult(std::string_view json);
std::optional<CniRequest> ParseCniRequest(std::string_view json);

}  // namespace inline_proxy
