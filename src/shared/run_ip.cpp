#include "shared/run_ip.hpp"

#include <sys/wait.h>
#include <unistd.h>

namespace inline_proxy {

bool RunIp(const std::vector<std::string>& args) {
    if (args.empty()) {
        return false;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(const_cast<char*>("/usr/bin/ip"));
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    const pid_t child = ::fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        ::execv("/usr/bin/ip", argv.data());
        _exit(127);
    }

    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace inline_proxy
