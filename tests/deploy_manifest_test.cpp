#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

namespace {

std::string ReadText(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

TEST(DeployManifestTest, KustomizationAndCoreManifestsExist) {
    EXPECT_TRUE(std::filesystem::exists("deploy/base/kustomization.yaml"));
    EXPECT_TRUE(std::filesystem::exists("deploy/base/proxy-daemonset.yaml"));
    EXPECT_TRUE(std::filesystem::exists("deploy/base/caddy-demo.yaml"));
}

TEST(DeployManifestTest, UsesProductizableInlineProxyNames) {
    const auto daemonset = ReadText("deploy/base/proxy-daemonset.yaml");
    const auto caddy = ReadText("deploy/base/caddy-demo.yaml");
    const auto installer = ReadText("deploy/base/proxy-installer-daemonset.yaml");

    EXPECT_NE(daemonset.find("inline-proxy-daemon"), std::string::npos);
    EXPECT_NE(installer.find("inline-proxy-installer"), std::string::npos);
    EXPECT_NE(caddy.find("inline-proxy.example.com/enabled"), std::string::npos);
}

TEST(DeployManifestTest, TargetsK3sCniBinaryDirectory) {
    const auto installer = ReadText("deploy/base/proxy-installer-daemonset.yaml");
    const auto script = ReadText("deploy/scripts/install-cni.sh");

    EXPECT_NE(installer.find("/var/lib/rancher/k3s/data/cni"), std::string::npos);
    EXPECT_NE(script.find("/host/var/lib/rancher/k3s/data/cni"), std::string::npos);
}

TEST(DeployManifestTest, InstallerAcceptsSymlinkedK3sCniPlugins) {
    const auto script = ReadText("deploy/scripts/install-cni.sh");

    EXPECT_NE(script.find("-type l"), std::string::npos);
}
