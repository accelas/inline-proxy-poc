#include "cni/yajl_parser.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include "yajl/yajl_tree.h"

namespace inline_proxy {
namespace {

struct YajlDeleter {
    void operator()(yajl_val value) const {
        if (value) {
            yajl_tree_free(value);
        }
    }
};

using YajlHandle = std::unique_ptr<std::remove_pointer_t<yajl_val>, YajlDeleter>;

std::optional<std::string> ReadString(yajl_val node, const char* key) {
    const auto child = yajl_object_get(node, key);
    if (!child) {
        return std::nullopt;
    }
    const char* value = yajl_string_value(child);
    if (!value) {
        yajl_tree_free(child);
        return std::nullopt;
    }
    std::string result(value);
    yajl_tree_free(child);
    return result;
}


std::optional<std::string> ReadRequiredString(yajl_val node, const char* key) {
    const auto value = ReadString(node, key);
    if (!value || value->empty()) {
        return std::nullopt;
    }
    return value;
}

std::optional<CniInterface> ParseInterface(yajl_val node) {
    if (!node || yajl_typeof(node) != yajl_t_object) {
        return std::nullopt;
    }

    auto name = ReadString(node, "name");
    if (!name) {
        return std::nullopt;
    }

    CniInterface iface;
    iface.name = std::move(*name);
    if (auto sandbox = ReadString(node, "sandbox")) {
        iface.sandbox = std::move(*sandbox);
    }
    return iface;
}

std::optional<PrevResult> ParsePrevResultNode(yajl_val node) {
    if (!node || yajl_typeof(node) != yajl_t_object) {
        return std::nullopt;
    }

    PrevResult result;
    const auto interfaces = yajl_object_get(node, "interfaces");
    if (interfaces) {
        if (yajl_typeof(interfaces) != yajl_t_array) {
            yajl_tree_free(interfaces);
            return std::nullopt;
        }
        const size_t count = yajl_array_length(interfaces);
        for (size_t index = 0; index < count; ++index) {
            const auto entry = yajl_array_get(interfaces, index);
            if (!entry) {
                continue;
            }
            if (auto parsed = ParseInterface(entry)) {
                result.interfaces.push_back(std::move(*parsed));
            }
            yajl_tree_free(entry);
        }
        yajl_tree_free(interfaces);
    }

    return result;
}

}  // namespace

std::optional<PrevResult> ParsePrevResult(std::string_view json) {
    std::string input(json);
    YajlHandle root(yajl_tree_parse(input.c_str(), nullptr, 0));
    if (!root) {
        return std::nullopt;
    }
    return ParsePrevResultNode(root.get());
}

std::optional<CniRequest> ParseCniRequest(std::string_view json) {
    std::string input(json);
    YajlHandle root(yajl_tree_parse(input.c_str(), nullptr, 0));
    if (!root) {
        return std::nullopt;
    }

    auto version = ReadRequiredString(root.get(), "cniVersion");
    if (!version) {
        return std::nullopt;
    }

    auto name = ReadRequiredString(root.get(), "name");
    if (!name) {
        return std::nullopt;
    }

    CniRequest request;
    request.cni_version = std::move(*version);
    request.name = std::move(*name);

    const auto prev_result = yajl_object_get(root.get(), "prevResult");
    if (prev_result) {
        request.prev_result = ParsePrevResultNode(prev_result);
        yajl_tree_free(prev_result);
        if (!request.prev_result) {
            return std::nullopt;
        }
    }

    return request;
}

}  // namespace inline_proxy
