#include <gtest/gtest.h>

#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>

#include "proxy/config.hpp"

namespace {

class ScopedEnvVar {
public:
    ScopedEnvVar(const char* name, const char* value) : name_(name) {
        if (const char* existing = std::getenv(name)) {
            previous_ = std::string(existing);
        }
        if (value) {
            ::setenv(name, value, 1);
        } else {
            ::unsetenv(name);
        }
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
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", nullptr);
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", nullptr);
    char arg0[] = "proxy_daemon";
    char* argv[] = {arg0};
    auto cfg = inline_proxy::ProxyConfig::FromArgs(1, argv);
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

    auto cfg = inline_proxy::ProxyConfig::FromArgs(3, argv);

    EXPECT_EQ(cfg.admin_port, 28080);
    EXPECT_EQ(cfg.transparent_port, 35001);
}

TEST(ProxyConfigTest, CliOverridesTakePrecedenceOverInvalidEnvValuesForSameField) {
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", "not-a-number");
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", "29001");

    char arg0[] = "proxy_daemon";
    char arg1[] = "--admin-port=28080";
    char* argv[] = {arg0, arg1};

    auto cfg = inline_proxy::ProxyConfig::FromArgs(2, argv);

    EXPECT_EQ(cfg.admin_port, 28080);
    EXPECT_EQ(cfg.transparent_port, 29001);
}

TEST(ProxyConfigTest, RejectsInvalidEnvPortValues) {
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", "not-a-number");
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", nullptr);
    char arg0[] = "proxy_daemon";
    char* argv[] = {arg0};

    EXPECT_THROW((void)inline_proxy::ProxyConfig::FromArgs(1, argv), std::invalid_argument);
}

TEST(ProxyConfigTest, RejectsInvalidCliPortValues) {
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", nullptr);
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", nullptr);
    char arg0[] = "proxy_daemon";
    char arg1[] = "--admin-port=abc";
    char* argv[] = {arg0, arg1};

    EXPECT_THROW((void)inline_proxy::ProxyConfig::FromArgs(2, argv), std::invalid_argument);
}

TEST(ProxyConfigTest, RejectsUnknownCliFlags) {
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", nullptr);
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", nullptr);

    char arg0[] = "proxy_daemon";
    char arg1[] = "--unknown-flag";
    char* argv[] = {arg0, arg1};

    EXPECT_THROW((void)inline_proxy::ProxyConfig::FromArgs(2, argv), std::invalid_argument);
}

TEST(ProxyConfigTest, RejectsUnknownInjectedEnvKeys) {
    EXPECT_THROW((void)inline_proxy::ProxyConfig::FromEnv({
                     {"INLINE_PROXY_ADMIN_PORT", "18080"},
                     {"INLINE_PROXY_EXTRA", "1"},
                 }),
                 std::invalid_argument);
}

TEST(ProxyConfigTest, RejectsUnknownRuntimeEnvKeys) {
    ScopedEnvVar unknown_env("INLINE_PROXY_EXTRA", "1");
    ScopedEnvVar admin_env("INLINE_PROXY_ADMIN_PORT", nullptr);
    ScopedEnvVar transparent_env("INLINE_PROXY_TRANSPARENT_PORT", nullptr);

    char arg0[] = "proxy_daemon";
    char* argv[] = {arg0};

    EXPECT_THROW((void)inline_proxy::ProxyConfig::FromArgs(1, argv), std::invalid_argument);
}
