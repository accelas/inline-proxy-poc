#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>

namespace inline_proxy {

std::optional<unsigned int> LinkIndex(const std::string& ifname) noexcept;
bool SetLinkUp(const std::string& ifname, bool up = true);
bool RenameLink(const std::string& ifname, const std::string& new_name);
bool DeleteLink(const std::string& ifname);
bool MoveLinkToNetns(const std::string& ifname, int netns_fd);
bool CreateVethPair(const std::string& left_ifname, const std::string& right_ifname);
bool AddLocalAddress(const std::string& ifname, const in_addr& address, std::uint8_t prefix_len = 32);
bool RemoveLocalAddress(const std::string& ifname,
                        const in_addr& address,
                        std::uint8_t prefix_len = 32);

}  // namespace inline_proxy
