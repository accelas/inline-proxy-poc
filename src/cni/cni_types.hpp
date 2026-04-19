#pragma once

#include <optional>
#include <string>
#include <vector>

namespace inline_proxy {

struct CniInterface {
    std::string name;
    std::optional<std::string> sandbox;
};

struct PrevResult {
    std::vector<CniInterface> interfaces;
};

struct CniRequest {
    std::string cni_version;
    std::string name;
    std::optional<PrevResult> prev_result;
    std::optional<std::string> prev_result_json;
};

}  // namespace inline_proxy
