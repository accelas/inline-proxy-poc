#include "cni/splice_repair.hpp"

#include <sys/stat.h>

#include <chrono>
#include <iostream>
#include <string>
#include <system_error>

#include "shared/state_store.hpp"

namespace inline_proxy {

namespace {

struct InodeId {
    dev_t dev;
    ino_t ino;
};

std::optional<InodeId> StatInode(const std::filesystem::path& p) {
    struct ::stat st {};
    if (::stat(p.c_str(), &st) != 0) {
        return std::nullopt;
    }
    return InodeId{st.st_dev, st.st_ino};
}

bool SameInode(const InodeId& a, const InodeId& b) {
    return a.dev == b.dev && a.ino == b.ino;
}

}  // namespace

SpliceRepairResult RepairOrphanedSplices(const SpliceExecutor& executor,
                                         std::filesystem::path current_proxy_netns,
                                         std::chrono::steady_clock::duration deadline) {
    SpliceRepairResult result;
    const auto& state_root = executor.options().state_root;

    std::error_code ec;
    if (!std::filesystem::exists(state_root, ec)) {
        return result;
    }

    const auto current_inode = StatInode(current_proxy_netns);
    if (!current_inode.has_value()) {
        std::cerr << "splice-repair: warning: cannot stat current proxy netns "
                  << current_proxy_netns
                  << "; intact-check disabled, all state files will be re-evaluated\n";
    }

    std::filesystem::directory_iterator dir_it(state_root, ec);
    if (ec) {
        std::cerr << "splice-repair: failed to open state dir " << state_root
                  << ": " << ec.message() << "\n";
        return result;
    }

    const auto deadline_at = std::chrono::steady_clock::now() + deadline;

    for (const auto& entry : dir_it) {
        const auto path = entry.path();
        if (path.filename().string().rfind("container-", 0) != 0) {
            continue;
        }
        if (path.extension() != ".json") {
            continue;
        }
        ++result.total_state_files;

        if (std::chrono::steady_clock::now() >= deadline_at) {
            ++result.skipped_deadline_exceeded;
            continue;
        }

        StateStore store(path);
        const auto fields_opt = store.Read();
        if (!fields_opt) {
            std::cerr << "splice-repair: parse failed for " << path << "\n";
            ++result.failed;
            continue;
        }
        const auto& fields = *fields_opt;
        const auto get = [&](const std::string& key) -> std::string {
            const auto it = fields.find(key);
            return it == fields.end() ? std::string{} : it->second;
        };

        const auto recorded_proxy = get("proxy_netns_path");
        if (current_inode.has_value()) {
            const auto recorded_inode = StatInode(recorded_proxy);
            if (recorded_inode.has_value() && SameInode(*recorded_inode, *current_inode)) {
                ++result.skipped_intact;
                continue;
            }
        }

        // Tasks 5-7 will add: workload-gone check, fabricate Pods + invocation, call HandleAdd.
        ++result.failed;
        std::cerr << "splice-repair: not yet implemented for " << path << "\n";
    }

    return result;
}

}  // namespace inline_proxy
