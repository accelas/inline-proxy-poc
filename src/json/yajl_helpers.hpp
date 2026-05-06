#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "yajl/yajl_tree.h"

namespace inline_proxy::json {

class Document {
public:
    static std::optional<Document> Parse(std::string_view input);

    Document(const Document&) = delete;
    Document& operator=(const Document&) = delete;
    Document(Document&&) noexcept = default;
    Document& operator=(Document&&) noexcept = default;
    ~Document() = default;

    yajl_val root() const { return root_.get(); }

private:
    struct Deleter {
        void operator()(yajl_val v) const noexcept;
    };

    explicit Document(yajl_val root) : root_(root) {}
    std::unique_ptr<std::remove_pointer_t<yajl_val>, Deleter> root_;
};

yajl_val ObjectGet(yajl_val obj, std::string_view key);
yajl_val ArrayAt(yajl_val arr, std::size_t index);
std::size_t ArrayLength(yajl_val arr);

struct ObjectEntry {
    std::string_view key;
    yajl_val value;
};
std::vector<ObjectEntry> ObjectEntries(yajl_val obj);

std::optional<std::string_view> AsString(yajl_val v);
std::optional<double>           AsNumber(yajl_val v);
std::optional<long long>        AsInteger(yajl_val v);
std::optional<bool>             AsBool(yajl_val v);
bool IsObject(yajl_val v);
bool IsArray(yajl_val v);

std::string Serialize(yajl_val v);

}  // namespace inline_proxy::json
