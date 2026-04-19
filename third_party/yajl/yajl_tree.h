#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum yajl_type_e {
    yajl_t_null = 0,
    yajl_t_bool = 1,
    yajl_t_number = 2,
    yajl_t_string = 3,
    yajl_t_array = 4,
    yajl_t_object = 5,
} yajl_type;

typedef struct yajl_val_s *yajl_val;

yajl_val yajl_tree_parse(const char *input, char *error_buffer, size_t error_buffer_size);
void yajl_tree_free(yajl_val value);

yajl_val yajl_tree_get(yajl_val value, const char *const *path, yajl_type type);

yajl_type yajl_typeof(yajl_val value);
yajl_val yajl_object_get(yajl_val value, const char *key);
yajl_val yajl_array_get(yajl_val value, size_t index);
size_t yajl_array_length(yajl_val value);
const char *yajl_string_value(yajl_val value);
double yajl_number_value(yajl_val value);
int yajl_bool_value(yajl_val value);

#ifdef __cplusplus
}
#endif
