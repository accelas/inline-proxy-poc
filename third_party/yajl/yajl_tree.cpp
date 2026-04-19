#include "yajl/yajl_tree.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

struct yajl_val_s {
    const nlohmann::json* view = nullptr;
    std::unique_ptr<nlohmann::json> owned;
};

namespace {

using Json = nlohmann::json;

static yajl_val MakeOwned(std::unique_ptr<Json> json) {
    auto* value = new yajl_val_s;
    value->view = json.get();
    value->owned = std::move(json);
    return value;
}

static yajl_val MakeView(const Json* json) {
    if (!json) {
        return nullptr;
    }
    auto* value = new yajl_val_s;
    value->view = json;
    return value;
}

static const Json* AsJson(yajl_val value) {
    return value ? value->view : nullptr;
}

static yajl_type TypeOfJson(const Json* json) {
    if (!json || json->is_null()) {
        return yajl_t_null;
    }
    if (json->is_boolean()) {
        return yajl_t_bool;
    }
    if (json->is_number()) {
        return yajl_t_number;
    }
    if (json->is_string()) {
        return yajl_t_string;
    }
    if (json->is_array()) {
        return yajl_t_array;
    }
    return yajl_t_object;
}

static void FillError(char* error_buffer, size_t error_buffer_size, const std::string& error) {
    if (!error_buffer || error_buffer_size == 0) {
        return;
    }
    std::snprintf(error_buffer, error_buffer_size, "%s", error.c_str());
    error_buffer[error_buffer_size - 1] = '\0';
}

}  // namespace

extern "C" {

yajl_val yajl_tree_parse(const char *input, char *error_buffer, size_t error_buffer_size) {
    try {
        auto json = std::make_unique<Json>(Json::parse(input ? input : ""));
        return MakeOwned(std::move(json));
    } catch (const std::exception& ex) {
        FillError(error_buffer, error_buffer_size, ex.what());
        return nullptr;
    }
}

void yajl_tree_free(yajl_val value) {
    delete value;
}

yajl_val yajl_tree_get(yajl_val value, const char *const *path, yajl_type type) {
    const Json* current = AsJson(value);
    if (!current) {
        return nullptr;
    }
    if (!path) {
        return TypeOfJson(current) == type ? MakeView(current) : nullptr;
    }
    for (const char* const* cursor = path; *cursor != nullptr; ++cursor) {
        if (!current->is_object()) {
            return nullptr;
        }
        auto it = current->find(*cursor);
        if (it == current->end()) {
            return nullptr;
        }
        current = &it.value();
    }
    if (TypeOfJson(current) != type) {
        return nullptr;
    }
    return MakeView(current);
}

yajl_type yajl_typeof(yajl_val value) {
    return TypeOfJson(AsJson(value));
}

yajl_val yajl_object_get(yajl_val value, const char *key) {
    const Json* json = AsJson(value);
    if (!json || !json->is_object() || !key) {
        return nullptr;
    }
    auto it = json->find(key);
    if (it == json->end()) {
        return nullptr;
    }
    return MakeView(&it.value());
}

yajl_val yajl_array_get(yajl_val value, size_t index) {
    const Json* json = AsJson(value);
    if (!json || !json->is_array() || index >= json->size()) {
        return nullptr;
    }
    return MakeView(&(*json)[index]);
}

size_t yajl_array_length(yajl_val value) {
    const Json* json = AsJson(value);
    if (!json || !json->is_array()) {
        return 0;
    }
    return json->size();
}

const char *yajl_string_value(yajl_val value) {
    const Json* json = AsJson(value);
    if (!json || !json->is_string()) {
        return nullptr;
    }
    return json->get_ref<const std::string&>().c_str();
}

double yajl_number_value(yajl_val value) {
    const Json* json = AsJson(value);
    if (!json || !json->is_number()) {
        return 0.0;
    }
    return json->get<double>();
}

int yajl_bool_value(yajl_val value) {
    const Json* json = AsJson(value);
    if (!json || !json->is_boolean()) {
        return 0;
    }
    return json->get<bool>() ? 1 : 0;
}

}  // extern "C"
