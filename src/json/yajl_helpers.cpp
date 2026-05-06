#include "json/yajl_helpers.hpp"

#include <cstring>
#include <utility>

#include "yajl/yajl_gen.h"
#include "yajl/yajl_tree.h"

namespace inline_proxy::json {

void Document::Deleter::operator()(yajl_val v) const noexcept {
    if (v != nullptr) {
        yajl_tree_free(v);
    }
}

std::optional<Document> Document::Parse(std::string_view input) {
    // yajl_tree_parse needs a NUL-terminated string; copy into a std::string.
    const std::string buffer(input);
    yajl_val root = yajl_tree_parse(buffer.c_str(), nullptr, 0);
    if (root == nullptr) {
        return std::nullopt;
    }
    return Document(root);
}

bool IsObject(yajl_val v) {
    return v != nullptr && YAJL_IS_OBJECT(v);
}

bool IsArray(yajl_val v) {
    return v != nullptr && YAJL_IS_ARRAY(v);
}

yajl_val ObjectGet(yajl_val obj, std::string_view key) {
    if (!IsObject(obj)) {
        return nullptr;
    }
    for (std::size_t i = 0; i < obj->u.object.len; ++i) {
        const char* k = obj->u.object.keys[i];
        if (k != nullptr && key.size() == std::strlen(k) &&
            std::memcmp(k, key.data(), key.size()) == 0) {
            return obj->u.object.values[i];
        }
    }
    return nullptr;
}

yajl_val ArrayAt(yajl_val arr, std::size_t index) {
    if (!IsArray(arr) || index >= arr->u.array.len) {
        return nullptr;
    }
    return arr->u.array.values[index];
}

std::size_t ArrayLength(yajl_val arr) {
    return IsArray(arr) ? arr->u.array.len : 0u;
}

std::vector<ObjectEntry> ObjectEntries(yajl_val obj) {
    std::vector<ObjectEntry> out;
    if (!IsObject(obj)) {
        return out;
    }
    out.reserve(obj->u.object.len);
    for (std::size_t i = 0; i < obj->u.object.len; ++i) {
        const char* k = obj->u.object.keys[i];
        out.push_back({std::string_view(k != nullptr ? k : ""),
                       obj->u.object.values[i]});
    }
    return out;
}

std::optional<std::string_view> AsString(yajl_val v) {
    if (v == nullptr || !YAJL_IS_STRING(v)) {
        return std::nullopt;
    }
    const char* s = YAJL_GET_STRING(v);
    return s == nullptr ? std::optional<std::string_view>{}
                        : std::optional<std::string_view>{s};
}

std::optional<double> AsNumber(yajl_val v) {
    if (v == nullptr || !YAJL_IS_NUMBER(v)) {
        return std::nullopt;
    }
    return YAJL_GET_DOUBLE(v);
}

std::optional<long long> AsInteger(yajl_val v) {
    if (v == nullptr || !YAJL_IS_INTEGER(v)) {
        return std::nullopt;
    }
    return YAJL_GET_INTEGER(v);
}

std::optional<bool> AsBool(yajl_val v) {
    if (v == nullptr) {
        return std::nullopt;
    }
    if (YAJL_IS_TRUE(v)) return true;
    if (YAJL_IS_FALSE(v)) return false;
    return std::nullopt;
}

namespace {

void GenerateNode(yajl_gen g, yajl_val v) {
    if (v == nullptr || YAJL_IS_NULL(v)) {
        yajl_gen_null(g);
        return;
    }
    if (YAJL_IS_TRUE(v)) {
        yajl_gen_bool(g, 1);
        return;
    }
    if (YAJL_IS_FALSE(v)) {
        yajl_gen_bool(g, 0);
        return;
    }
    if (YAJL_IS_STRING(v)) {
        const char* s = YAJL_GET_STRING(v);
        yajl_gen_string(g, reinterpret_cast<const unsigned char*>(s),
                        std::strlen(s));
        return;
    }
    if (YAJL_IS_NUMBER(v)) {
        // Use the original lexed text (preserves integer/double distinction
        // and avoids precision-changing reformats).
        const char* num = v->u.number.r;
        yajl_gen_number(g, num, std::strlen(num));
        return;
    }
    if (YAJL_IS_ARRAY(v)) {
        yajl_gen_array_open(g);
        for (std::size_t i = 0; i < v->u.array.len; ++i) {
            GenerateNode(g, v->u.array.values[i]);
        }
        yajl_gen_array_close(g);
        return;
    }
    if (YAJL_IS_OBJECT(v)) {
        yajl_gen_map_open(g);
        for (std::size_t i = 0; i < v->u.object.len; ++i) {
            const char* k = v->u.object.keys[i];
            yajl_gen_string(g, reinterpret_cast<const unsigned char*>(k),
                            std::strlen(k));
            GenerateNode(g, v->u.object.values[i]);
        }
        yajl_gen_map_close(g);
    }
}

}  // namespace

std::string Serialize(yajl_val v) {
    yajl_gen g = yajl_gen_alloc(nullptr);
    if (g == nullptr) {
        return {};
    }
    yajl_gen_config(g, yajl_gen_beautify, 0);
    yajl_gen_config(g, yajl_gen_validate_utf8, 0);
    GenerateNode(g, v);

    const unsigned char* buf = nullptr;
    std::size_t len = 0;
    yajl_gen_get_buf(g, &buf, &len);
    std::string out(reinterpret_cast<const char*>(buf), len);
    yajl_gen_free(g);
    return out;
}

}  // namespace inline_proxy::json
