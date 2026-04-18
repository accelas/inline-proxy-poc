#include <gtest/gtest.h>

#include <cstdlib>
#include <optional>
#include <string>

#include "proxy/config.hpp"

namespace {

class ScopedEnvVar {
public:
    ScopedEnvVar(const char* name, const char* value) : name_(name) {
        if (const char* existing = std::getenv(name)) {
            previous_ = std::string(existing);
        }
        ::setenv(name, value, 1);
    }

    ~ScopedEnvVar() {
        if (previous_) {
            ::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            ::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

}  // namespace

TEST(ProxyConfigTest, ParsesDefaultAdminAndTransparentPorts) {
    auto cfg = inline_proxy::ProxyConfig::FromEnv({});
    EXPECT_EQ(cfg.admin_port, 8080);
    EXPECT_EQ(cfg.transparent_port, 15001);
}

TEST(ProxyConfigTest, ParsesEnvOverridesForPorts) {
    auto cfg = inline_proxy::ProxyConfig::FromEnv({
        {"INLINE_PROXY_ADMIN_PORT", "18080"},
        {"INLINE_PROXY_TRANSPARENT_PORT", "25001"},
    });

    EXPECT_EQ(cfg.admin_port, 18080);
    EXPECT_EQ(cfg.transparent_port, 25001);
}

TEST(ProxyConfigTest, ParsesCliOverridesForPorts) {
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", "19080");
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", "29001");

    char arg0[] = "proxy_daemon";
    char arg1[] = "--admin-port=28080";
    char arg2[] = "--transparent-port=35001";
    char* argv[] = {arg0, arg1, arg2};

    auto cfg = inline_proxy::ProxyConfig::FromEnv(3, argv);

    EXPECT_EQ(cfg.admin_port, 28080);
    EXPECT_EQ(cfg.transparent_port, 35001);
}
