#include "cni/splice_repair.hpp"

#include <sys/stat.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>

#include "cni/cni_types.hpp"
#include "cni/k8s_client.hpp"  // for PodInfo
#include "cni/yajl_parser.hpp"
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
    const bool dir_exists = std::filesystem::exists(state_root, ec);
    if (ec) {
        std::cerr << "splice-repair: cannot access state dir " << state_root
                  << ": " << ec.message() << "\n";
        return result;
    }
    if (!dir_exists) {
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

    try {
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
                break;
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

            const auto workload_path = get("workload_netns_path");
            if (workload_path.empty() ||
                !std::filesystem::exists(workload_path, ec)) {
                ++result.skipped_workload_gone;
                continue;
            }

            const auto pod_name = get("pod_name");
            const auto pod_namespace = get("pod_namespace");
            const auto proxy_name = get("proxy_name");
            const auto proxy_namespace = get("proxy_namespace");
            const auto proxy_node_name = get("proxy_node_name");
            const auto container_id = get("container_id");
            const auto ifname = get("ifname");
            const auto prev_result_raw = get("prev_result");
            if (container_id.empty() || ifname.empty() ||
                prev_result_raw.empty() || proxy_node_name.empty()) {
                std::cerr << "splice-repair: incomplete state file " << path << "\n";
                ++result.failed;
                continue;
            }

            // HandleDel uses the same wrap-and-parse recipe at splice_executor.cpp:404-406.
            const std::string envelope =
                R"({"cniVersion":"1.0.0","name":"restore","prevResult":)" +
                prev_result_raw + "}";
            auto request_opt = ParseCniRequest(envelope);
            if (!request_opt) {
                std::cerr << "splice-repair: malformed prev_result in " << path << "\n";
                ++result.failed;
                continue;
            }

            PodInfo workload_pod;
            workload_pod.name = pod_name;
            workload_pod.namespace_name = pod_namespace;
            workload_pod.node_name = proxy_node_name;
            workload_pod.running = true;
            workload_pod.annotations["inline-proxy.example.com/enabled"] = "true";

            PodInfo proxy_pod;
            proxy_pod.name = proxy_name;
            proxy_pod.namespace_name =
                proxy_namespace.empty() ? "inline-proxy-system" : proxy_namespace;
            proxy_pod.node_name = proxy_node_name;
            proxy_pod.running = true;
            proxy_pod.labels["app"] = "inline-proxy";

            // Per-call executor copy with proxy_netns_path overridden to the
            // current proxy netns. Cheap — SpliceExecutor holds only an options
            // struct. Do NOT set workload_netns_path: ResolveWorkloadNetnsPath
            // derives it from prev_result.interfaces[].sandbox, which is what
            // the state file already carries.
            auto per_call_options = executor.options();
            per_call_options.proxy_netns_path = current_proxy_netns;
            SpliceExecutor per_call_executor(std::move(per_call_options));

            CniInvocation invocation;
            invocation.request = std::move(*request_opt);
            invocation.container_id = container_id;
            invocation.ifname = ifname;

            // HandleAdd's third arg is `const std::optional<PodInfo>&`; PodInfo
            // converts implicitly.
            const auto handle_result =
                per_call_executor.HandleAdd(invocation, workload_pod, proxy_pod);
            if (handle_result.success) {
                ++result.repaired;
            } else {
                std::cerr << "splice-repair: HandleAdd failed for " << path
                          << ": " << handle_result.stderr_text << "\n";
                ++result.failed;
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "splice-repair: directory iteration aborted: "
                  << e.what() << "\n";
    }

    return result;
}

}  // namespace inline_proxy
