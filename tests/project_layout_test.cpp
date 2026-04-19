#include <filesystem>

#include <gtest/gtest.h>

TEST(ProjectLayoutTest, ExpectedDirectoriesExist) {
    EXPECT_TRUE(std::filesystem::exists("src/shared/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/proxy/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/cni/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/bpf/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("deploy/README.md"));
}
