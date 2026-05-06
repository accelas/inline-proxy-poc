#include "cni/yajl_parser.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "json/yajl_helpers.hpp"

namespace inline_proxy {
namespace {

namespace ip = inline_proxy::json;

std::optional<std::string> ReadString(yajl_val obj, const char* key) {
    auto sv = ip::AsString(ip::ObjectGet(obj, key));
    if (!sv.has_value()) {
        return std::nullopt;
    }
    return std::string(*sv);
}

std::optional<std::string> ReadRequiredString(yajl_val obj, const char* key) {
    auto value = ReadString(obj, key);
    if (!value.has_value() || value->empty()) {
        return std::nullopt;
    }
    return value;
}

std::optional<CniInterface> ParseInterface(yajl_val node) {
    if (!ip::IsObject(node)) {
        return std::nullopt;
    }
    auto name = ReadString(node, "name");
    if (!name.has_value()) {
        return std::nullopt;
    }
    CniInterface iface;
    iface.name = std::move(*name);
    if (auto sandbox = ReadString(node, "sandbox"); sandbox.has_value()) {
        iface.sandbox = std::move(*sandbox);
    }
    return iface;
}

std::optional<PrevResult> ParsePrevResultNode(yajl_val node) {
    if (!ip::IsObject(node)) {
        return std::nullopt;
    }
    PrevResult result;
    yajl_val interfaces = ip::ObjectGet(node, "interfaces");
    if (interfaces != nullptr) {
        if (!ip::IsArray(interfaces)) {
            return std::nullopt;
        }
        for (std::size_t i = 0; i < ip::ArrayLength(interfaces); ++i) {
            if (auto parsed = ParseInterface(ip::ArrayAt(interfaces, i));
                parsed.has_value()) {
                result.interfaces.push_back(std::move(*parsed));
            }
        }
    }
    return result;
}

}  // namespace

std::optional<PrevResult> ParsePrevResult(std::string_view json) {
    auto doc = ip::Document::Parse(json);
    if (!doc.has_value()) {
        return std::nullopt;
    }
    return ParsePrevResultNode(doc->root());
}

std::optional<CniRequest> ParseCniRequest(std::string_view json) {
    auto doc = ip::Document::Parse(json);
    if (!doc.has_value()) {
        return std::nullopt;
    }
    yajl_val root = doc->root();

    auto version = ReadRequiredString(root, "cniVersion");
    if (!version.has_value()) {
        return std::nullopt;
    }
    auto name = ReadRequiredString(root, "name");
    if (!name.has_value()) {
        return std::nullopt;
    }

    CniRequest request;
    request.cni_version = std::move(*version);
    request.name = std::move(*name);

    if (yajl_val prev = ip::ObjectGet(root, "prevResult"); prev != nullptr) {
        auto parsed = ParsePrevResultNode(prev);
        if (!parsed.has_value()) {
            return std::nullopt;
        }
        request.prev_result = std::move(parsed);
        request.prev_result_json = ip::Serialize(prev);
    }

    return request;
}

}  // namespace inline_proxy
