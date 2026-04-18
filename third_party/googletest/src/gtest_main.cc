#include "gtest/gtest.h"

#include <cstdlib>
#include <filesystem>
#include <string>

namespace {

void EnterWorkspaceRunfilesRoot() {
    const char* srcdir = std::getenv("TEST_SRCDIR");
    const char* workspace = std::getenv("TEST_WORKSPACE");
    if (srcdir == nullptr || workspace == nullptr) {
        return;
    }

    std::filesystem::path workspace_root = std::filesystem::path(srcdir) / workspace;
    std::error_code ec;
    std::filesystem::current_path(workspace_root, ec);
}

}  // namespace

int main(int argc, char** argv) {
    EnterWorkspaceRunfilesRoot();
    ::testing::InitGoogleTest(&argc, argv);
    return ::testing::RunAllTests();
}
