#include "cni/yajl_parser.hpp"

#include <memory>
#include <optional>
#include <sstream>
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

void AppendEscaped(std::ostringstream& out, std::string_view value) {
    for (char ch : value) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch; break;
        }
    }
}

std::string RenderPrevResultJson(const PrevResult& prev_result) {
    std::ostringstream out;
    out << "{\"interfaces\":[";
    for (std::size_t index = 0; index < prev_result.interfaces.size(); ++index) {
        if (index > 0) {
            out << ',';
        }
        const auto& iface = prev_result.interfaces[index];
        out << "{\"name\":\"";
        AppendEscaped(out, iface.name);
        out << "\"";
        if (iface.sandbox.has_value()) {
            out << ",\"sandbox\":\"";
            AppendEscaped(out, *iface.sandbox);
            out << "\"";
        }
        out << "}";
    }
    out << "]}";
    return out.str();
}

bool IsJsonWhitespace(char ch) {
    return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
}

std::optional<std::size_t> FindKeyValueStart(std::string_view input, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t pos = 0;
    while (true) {
        pos = input.find(needle, pos);
        if (pos == std::string_view::npos) {
            return std::nullopt;
        }

        std::size_t cursor = pos + needle.size();
        while (cursor < input.size() && IsJsonWhitespace(input[cursor])) {
            ++cursor;
        }
        if (cursor >= input.size() || input[cursor] != ':') {
            pos += 1;
            continue;
        }
        ++cursor;
        while (cursor < input.size() && IsJsonWhitespace(input[cursor])) {
            ++cursor;
        }
        if (cursor >= input.size()) {
            return std::nullopt;
        }
        return cursor;
    }
}

std::optional<std::size_t> ConsumeJsonString(std::string_view input, std::size_t pos) {
    if (pos >= input.size() || input[pos] != '"') {
        return std::nullopt;
    }
    ++pos;
    while (pos < input.size()) {
        const char ch = input[pos++];
        if (ch == '"') {
            return pos;
        }
        if (ch == '\\' && pos < input.size()) {
            ++pos;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> ConsumeJsonValue(std::string_view input, std::size_t pos) {
    if (pos >= input.size()) {
        return std::nullopt;
    }

    if (input[pos] == '"') {
        return ConsumeJsonString(input, pos);
    }

    if (input[pos] == '{' || input[pos] == '[') {
        const char open = input[pos];
        const char close = (open == '{') ? '}' : ']';
        int depth = 0;
        bool in_string = false;
        bool escaped = false;
        for (; pos < input.size(); ++pos) {
            const char ch = input[pos];
            if (in_string) {
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (ch == '\\') {
                    escaped = true;
                    continue;
                }
                if (ch == '"') {
                    in_string = false;
                }
                continue;
            }
            if (ch == '"') {
                in_string = true;
                continue;
            }
            if (ch == open) {
                ++depth;
            } else if (ch == close) {
                --depth;
                if (depth == 0) {
                    return pos + 1;
                }
            }
        }
        return std::nullopt;
    }

    std::size_t cursor = pos;
    while (cursor < input.size()) {
        const char ch = input[cursor];
        if (ch == ',' || ch == '}' || ch == ']' || IsJsonWhitespace(ch)) {
            break;
        }
        ++cursor;
    }
    return cursor;
}

std::optional<std::string> ExtractRawJsonValue(std::string_view input, std::string_view key) {
    const auto start = FindKeyValueStart(input, key);
    if (!start) {
        return std::nullopt;
    }
    const auto end = ConsumeJsonValue(input, *start);
    if (!end || *end <= *start) {
        return std::nullopt;
    }
    return std::string(input.substr(*start, *end - *start));
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
        request.prev_result_json = ExtractRawJsonValue(input, "prevResult");
        yajl_tree_free(prev_result);
        if (!request.prev_result) {
            return std::nullopt;
        }
        if (!request.prev_result_json.has_value()) {
            request.prev_result_json = RenderPrevResultJson(*request.prev_result);
        }
    }

    return request;
}

}  // namespace inline_proxy
