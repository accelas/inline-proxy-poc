#include <gtest/gtest.h>

#include <string>

#include "json/yajl_helpers.hpp"

namespace ip = inline_proxy::json;

TEST(JsonYajlHelpersTest, ParsesValidObject) {
    auto doc = ip::Document::Parse(R"({"a":1,"b":"x"})");
    ASSERT_TRUE(doc.has_value());
    ASSERT_TRUE(ip::IsObject(doc->root()));
}

TEST(JsonYajlHelpersTest, RejectsMalformedJson) {
    auto doc = ip::Document::Parse("{not json");
    EXPECT_FALSE(doc.has_value());
}

TEST(JsonYajlHelpersTest, ObjectGetFindsKey) {
    auto doc = ip::Document::Parse(R"({"a":42,"b":"x"})");
    ASSERT_TRUE(doc.has_value());
    yajl_val a = ip::ObjectGet(doc->root(), "a");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(ip::AsInteger(a), 42);
}

TEST(JsonYajlHelpersTest, ObjectGetMissingKeyReturnsNull) {
    auto doc = ip::Document::Parse(R"({"a":1})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::ObjectGet(doc->root(), "missing"), nullptr);
}

TEST(JsonYajlHelpersTest, ObjectGetOnNonObjectReturnsNull) {
    auto doc = ip::Document::Parse(R"([1,2])");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::ObjectGet(doc->root(), "any"), nullptr);
}

TEST(JsonYajlHelpersTest, ArrayLengthAndArrayAt) {
    auto doc = ip::Document::Parse(R"([10,20,30])");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::ArrayLength(doc->root()), 3u);
    EXPECT_EQ(ip::AsInteger(ip::ArrayAt(doc->root(), 1)), 20);
    EXPECT_EQ(ip::ArrayAt(doc->root(), 99), nullptr);
}

TEST(JsonYajlHelpersTest, ArrayLengthOnNonArrayIsZero) {
    auto doc = ip::Document::Parse(R"({"a":1})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::ArrayLength(doc->root()), 0u);
}

TEST(JsonYajlHelpersTest, ObjectEntriesPreservesOrder) {
    auto doc = ip::Document::Parse(R"({"first":1,"second":"x","third":true})");
    ASSERT_TRUE(doc.has_value());
    auto entries = ip::ObjectEntries(doc->root());
    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(entries[0].key, "first");
    EXPECT_EQ(entries[1].key, "second");
    EXPECT_EQ(entries[2].key, "third");
    EXPECT_EQ(ip::AsInteger(entries[0].value), 1);
    EXPECT_EQ(ip::AsString(entries[1].value), "x");
    EXPECT_EQ(ip::AsBool(entries[2].value), true);
}

TEST(JsonYajlHelpersTest, AsStringWrongTypeReturnsNullopt) {
    auto doc = ip::Document::Parse(R"({"a":1})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_FALSE(ip::AsString(ip::ObjectGet(doc->root(), "a")).has_value());
    EXPECT_FALSE(ip::AsString(nullptr).has_value());
}

TEST(JsonYajlHelpersTest, AsNumberAndAsInteger) {
    auto doc = ip::Document::Parse(R"({"i":7,"d":3.5})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::AsInteger(ip::ObjectGet(doc->root(), "i")), 7);
    EXPECT_DOUBLE_EQ(*ip::AsNumber(ip::ObjectGet(doc->root(), "d")), 3.5);
}

TEST(JsonYajlHelpersTest, AsBoolAndType) {
    auto doc = ip::Document::Parse(R"({"flag":true})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::AsBool(ip::ObjectGet(doc->root(), "flag")), true);
    EXPECT_TRUE(ip::IsObject(doc->root()));
    EXPECT_FALSE(ip::IsArray(doc->root()));
}

TEST(JsonYajlHelpersTest, SerializeRoundTripPreservesOrder) {
    const std::string original = R"({"dns":{"nameservers":["1.1.1.1"]},"interfaces":[{"name":"eth0"}]})";
    auto doc = ip::Document::Parse(original);
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::Serialize(doc->root()), original);
}

TEST(JsonYajlHelpersTest, SerializeSubtreeOnly) {
    auto doc = ip::Document::Parse(R"({"a":1,"sub":{"x":"y"}})");
    ASSERT_TRUE(doc.has_value());
    EXPECT_EQ(ip::Serialize(ip::ObjectGet(doc->root(), "sub")), R"({"x":"y"})");
}
