# Switch JSON parsing to real yajl

## Background

The repo's JSON code is a layered fiction. `third_party/yajl/` looks like
the [lloyd/yajl](https://github.com/lloyd/yajl) C library — same
`yajl_tree.h` filename, same `yajl_val` typedef, same function names
(`yajl_tree_parse`, `yajl_object_get`, `yajl_array_get`,
`yajl_string_value`, `yajl_typeof`, `yajl_array_length`, `yajl_tree_free`).
It is not yajl. The implementation under `third_party/yajl/yajl_tree.cpp`
is a 165-line C++ shim that includes `<nlohmann/json.hpp>` and translates
each shim call into nlohmann operations. The shim wires into Bazel as a
local module (`bazel_dep(name = "yajl") + local_path_override → third_party/yajl`).

The shim leaks an unidiomatic ownership rule: every call to
`yajl_object_get` / `yajl_array_get` `new`s a fresh `yajl_val_s` wrapper,
and the shim's API obliges callers to `yajl_tree_free` each child.
`src/cni/yajl_parser.cpp` does exactly that — six `yajl_tree_free(child)`
calls on intermediate nodes. Real yajl has the opposite rule: children
are non-owning views into the root tree; freeing one is undefined
behavior, freeing the root frees everything.

The one consumer of the shim, `src/cni/yajl_parser.cpp`, has a second
problem. About 230 of its 386 lines are a hand-rolled JSON tokenizer
(`IsJsonWhitespace`, `SkipJsonWhitespace`, `ParseHexDigit`,
`DecodeJsonEscape`, `DecodeJsonStringToken`, `FindKeyValueStart`,
`ConsumeJsonString`, `ConsumeJsonValue`, `ExtractRawJsonValue`). Its
sole purpose is to extract the raw source-byte slice of the
`prevResult` value into `request.prev_result_json`, even when the source
spells the key as `"prevResult"`. Downstream code (the splice
executor and the state-store reload path) only ever re-parses that
string; nothing inspects it as bytes at runtime. The hand-rolled
scanner exists because a tree parser can't reproduce arbitrary source
formatting. The byte-exact behavior is asserted by exactly one test
(`PreservesPrevResultJsonForEscapedPrevResultKey`).

Two more files (`src/cni/splice_executor.cpp`,
`src/cni/k8s_client.cpp`) include `<nlohmann/json.hpp>` directly,
bypassing the shim entirely. Both do parse-only work — no
serialization, except for one `item.dump()` round-trip in
`ParsePodList` that exists only to call `ParsePodInfo(string_view)`
on each list element.

## Goal

Move the project to one real JSON library — upstream lloyd/yajl,
vendored — and remove every trace of the shim and of `nlohmann::json`
from `src/` and `third_party/`. After this change, `grep -RIn nlohmann
src/ third_party/yajl/` returns nothing, and the only `yajl_tree_free`
in `src/` lives inside the helper module's RAII deleter. The
hand-rolled tokenizer in `yajl_parser.cpp` is gone. All CNI tests pass.

Non-goals:

- Migrating off whatever transitive include path currently provides
  `<nlohmann/json.hpp>` (probably system headers or a toolchain).
  Once nothing in `src/` depends on it, it can be removed by a
  separate cleanup PR.
- Touching the `.worktrees/*` snapshots in the working tree —
  pre-existing, unrelated.
- Adding a polished C++ JSON facade (e.g., a `JsonValue` class with
  operator overloads). The helper module is deliberately small and
  function-shaped.

## Design

### Vendor the real yajl source

Replace the contents of `third_party/yajl/` with the upstream
lloyd/yajl source tree (BSD-2-Clause, last release tag 2.1.0).
Concretely:

- **Drop:** the shim `yajl_tree.h` / `yajl_tree.cpp`.
- **Add:** the upstream `src/` C sources — `yajl_alloc.c`, `yajl_buf.c`,
  `yajl_encode.c`, `yajl_gen.c`, `yajl_lex.c`, `yajl_parser.c`,
  `yajl_tree.c`, `yajl_version.c` — and the public headers under
  `src/api/` (`yajl_common.h`, `yajl_parse.h`, `yajl_tree.h`,
  `yajl_gen.h`, etc.). Hand-write the otherwise-CMake-generated
  `yajl_version.h` (two `#define`s).
- **Add:** upstream `LICENSE`, matching the `third_party/libbpf/LICENSE.*`
  pattern.
- **Keep:** `third_party/yajl/MODULE.bazel` as `module(name = "yajl",
  version = "0.0.0")`. `MODULE.bazel`'s `bazel_dep` + `local_path_override`
  is unchanged.

Rewritten `third_party/yajl/BUILD.bazel`:

```python
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "yajl",
    srcs = glob(["src/*.c"]),
    hdrs = glob(["src/api/*.h"]) + glob(["src/*.h"]),
    includes = ["src", "src/api"],
    strip_include_prefix = "src/api",
)
```

`strip_include_prefix = "src/api"` lets existing `#include "yajl/yajl_tree.h"`
keep working — but pointing at the real header now.

### Helper module: `src/json/yajl_helpers.{hpp,cpp}`

A small free-function helper layer over real yajl. No class hierarchy,
no operator overloads, no type-erased variant. Lives in its own Bazel
target so any consumer can depend on it without dragging CNI deps
along.

```cpp
namespace inline_proxy::json {

// Owning wrapper for a parsed yajl tree. Children are non-owning views
// into the root — callers must NEVER free intermediate yajl_val handles.
class Document {
public:
    static std::optional<Document> Parse(std::string_view input);
    yajl_val root() const { return root_.get(); }
private:
    struct Deleter { void operator()(yajl_val v) const; };
    std::unique_ptr<std::remove_pointer_t<yajl_val>, Deleter> root_;
};

// Object/array navigation — return non-owning child views.
yajl_val ObjectGet(yajl_val obj, std::string_view key);
yajl_val ArrayAt(yajl_val arr, std::size_t index);
std::size_t ArrayLength(yajl_val arr);

// Iteration: macro/struct dance lives here, not in callers.
struct ObjectEntry { std::string_view key; yajl_val value; };
std::vector<ObjectEntry> ObjectEntries(yajl_val obj);

// Typed accessors — std::nullopt if wrong type / null / missing.
std::optional<std::string_view> AsString(yajl_val v);
std::optional<double>           AsNumber(yajl_val v);
std::optional<long long>        AsInteger(yajl_val v);
std::optional<bool>             AsBool(yajl_val v);
bool IsObject(yajl_val v);
bool IsArray(yajl_val v);

// Compact JSON serialization of a subtree (uses yajl_gen).
std::string Serialize(yajl_val v);

}  // namespace inline_proxy::json
```

Properties:

- `Document` owns the root via RAII; consumers never call
  `yajl_tree_free` directly. This single rule eliminates the shim's
  bug-shaped per-child free pattern.
- `AsString` returns `std::string_view` into the yajl-owned buffer
  (zero copy); `Document` keeps it alive. Callers that need a string
  outliving the doc copy explicitly.
- `Serialize` is the one new behavior: it wraps `yajl_gen` to produce
  compact JSON for any subtree, replacing the hand-rolled raw-byte
  extractor in `yajl_parser.cpp`.

### Consumer rewrites

**`src/cni/yajl_parser.cpp`** — written from scratch against the
helper module:

- `ParsePrevResult` / `ParseCniRequest` / `ParseInterface` /
  `ParsePrevResultNode` use `json::Document::Parse`, `ObjectGet`,
  `ArrayLength` + `ArrayAt`, `AsString`, `IsObject` / `IsArray`.
- Every `yajl_tree_free(child)` call disappears — children are views.
- The hand-rolled tokenizer (Half B above, ~230 lines) is **deleted**.
  `request.prev_result_json` is populated by
  `json::Serialize(prev_result_value)`.
- The file shrinks from 386 lines to roughly the size of the
  consumer half (~150 lines).

**`src/cni/k8s_client.cpp`** — mechanical translation:

- `Json::parse(json, nullptr, false)` + `is_discarded()` → `Document::Parse(json)`
  + `has_value()`.
- `parsed.find(key)` → `json::ObjectGet(root, key)`.
- `value.get<std::string>()` → `json::AsString(value)`.
- `for (const auto& [name, item] : value.items())` → `for (const auto&
  entry : json::ObjectEntries(value))`.
- `ReadString` and `ReadStringMap` rewrite directly against the
  helpers.
- **Refactor `ParsePodList`:** split `ParsePodInfo` into
  `ParsePodInfoFromValue(yajl_val)` (does the work) plus a thin
  `ParsePodInfo(string_view)` (parses then delegates). `ParsePodList`
  iterates `ArrayLength`/`ArrayAt` and calls the value-taking
  overload directly, eliminating the `item.dump()` re-parse.

**`src/cni/splice_executor.cpp`** — same pattern:

- One parse function, `ParseWorkloadNetworkConfig`.
- nlohmann's `is_number_unsigned()` → `AsInteger(v)` returning
  `long long`, with a `value >= 0` check before downcasting to
  `unsigned int`. Test data uses small non-negative interface
  indexes, so this covers it.
- `#include <nlohmann/json.hpp>` removed; `using Json = nlohmann::json;`
  removed.

### Bazel deps

- New package `src/json/BUILD.bazel`:

  ```python
  cc_library(
      name = "yajl_helpers",
      srcs = ["yajl_helpers.cpp"],
      hdrs = ["yajl_helpers.hpp"],
      deps = ["@yajl//:yajl"],
      include_prefix = "json",
  )
  ```

- `src/cni/BUILD.bazel`:
  - `cni_parser`: drop direct `@yajl//:yajl`, add `//src/json:yajl_helpers`.
  - `k8s_client`: add `//src/json:yajl_helpers`.
  - `cni_splice`: add `//src/json:yajl_helpers` explicitly (it gets it
    transitively, but the file uses the helpers directly).

### Tests

- `tests/cni_yajl_parser_test.cpp` —
  `PreservesPrevResultJsonForEscapedPrevResultKey` renamed to
  `SerializesPrevResultSubtreeAsCompactJson`. Expected string verified
  against actual `yajl_gen` output; it should already match (the
  current expected value is in canonical compact form), but if any
  byte diverges, the expectation is updated to reflect the new
  semantics.
- New `tests/json_yajl_helpers_test.cpp`: parse / missing key /
  wrong-type accessor / array iteration / object iteration /
  Serialize round-trip / parse-error path. Wired into `tests/BUILD.bazel`.
- All other CNI tests unchanged; they test behavior, not internals.

### Semantic change to `prev_result_json`

`prev_result_json` switches from "exact source bytes between the
opening and closing of the prevResult value" to "yajl's compact
serialization of the parsed prevResult subtree."

| | Today (raw extractor) | After (yajl_gen) |
|---|---|---|
| Object key order | source order | source order (yajl_tree preserves) |
| Whitespace | as in source | always compact |
| Numbers | as written (`1.0`, `1e2`) | normalized (`1`, `100`) |
| String escapes | as written (`"aAb"`) | decoded then minimally re-escaped |

Downstream callers re-parse the string in every case
(`ParseWorkloadNetworkConfig` re-parses; the state-store reload path
re-parses). Nothing renders `prev_result_json` to a human or compares
it byte-for-byte at runtime. The semantic change is invisible in
production.

## Verification

Before claiming done:

1. `bazel build //...` clean.
2. `bazel test //...` all pass.
3. `grep -RIn nlohmann src/ third_party/yajl/` returns zero hits.
4. `grep -RIn 'yajl_tree_free' src/` returns hits only inside
   `src/json/yajl_helpers.cpp`'s `Document::Deleter`.
5. `grep -RIn 'yajl_object_get\|yajl_array_get\|yajl_string_value\|yajl_typeof\|yajl_array_length' src/`
   returns hits only inside `src/json/yajl_helpers.cpp` (the helpers
   live there; consumers go through them).

## Process

Work happens on a fresh git worktree (branch `real-yajl`, off `main`)
created via the `using-git-worktrees` skill. Implementation follows
the plan that comes out of `writing-plans` next.
