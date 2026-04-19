#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>

namespace inline_proxy {

using StateFields = std::map<std::string, std::string>;

class StateStore {
public:
    explicit StateStore(std::filesystem::path path);

    const std::filesystem::path& path() const noexcept;

    bool Write(const StateFields& fields) const;
    std::optional<StateFields> Read() const;
    bool Remove() const;

private:
    std::filesystem::path path_;
};

}  // namespace inline_proxy
