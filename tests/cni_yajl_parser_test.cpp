#include <gtest/gtest.h>

#include "cni/yajl_parser.hpp"

TEST(CniYajlParserTest, ParsesAnnotatedPodAddRequest) {
    std::string json = R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->cni_version, "1.0.0");
    EXPECT_EQ(req->name, "k8s-pod-network");
    ASSERT_TRUE(req->prev_result.has_value());
    EXPECT_TRUE(req->prev_result->interfaces.empty());
}

TEST(CniYajlParserTest, ParsesPrevResultInterfaces) {
    std::string json = R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    ASSERT_TRUE(req.has_value());
    ASSERT_TRUE(req->prev_result.has_value());
    ASSERT_EQ(req->prev_result->interfaces.size(), 1u);
    EXPECT_EQ(req->prev_result->interfaces[0].name, "eth0");
    ASSERT_TRUE(req->prev_result->interfaces[0].sandbox.has_value());
    EXPECT_EQ(*req->prev_result->interfaces[0].sandbox, "/var/run/netns/test");
}

TEST(CniYajlParserTest, PreservesPrevResultJsonForEscapedPrevResultKey) {
    std::string json =
        R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prev\u0052esult":{"dns":{"nameservers":["1.1.1.1"]},"interfaces":[{"name":"eth0"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    ASSERT_TRUE(req.has_value());
    ASSERT_TRUE(req->prev_result.has_value());
    ASSERT_TRUE(req->prev_result_json.has_value());
    EXPECT_EQ(*req->prev_result_json,
              R"({"dns":{"nameservers":["1.1.1.1"]},"interfaces":[{"name":"eth0"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]})");
}

TEST(CniYajlParserTest, RejectsMissingName) {
    std::string json = R"({"cniVersion":"1.0.0","prevResult":{"interfaces":[]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    EXPECT_FALSE(req.has_value());
}

TEST(CniYajlParserTest, RejectsEmptyName) {
    std::string json = R"({"cniVersion":"1.0.0","name":"","prevResult":{"interfaces":[]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    EXPECT_FALSE(req.has_value());
}
