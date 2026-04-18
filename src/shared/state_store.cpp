#include "shared/state_store.hpp"

#include <cctype>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

#include "shared/scoped_fd.hpp"

namespace inline_proxy {
namespace {

std::string EscapeJsonString(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 8);
    for (unsigned char ch : input) {
        switch (ch) {
            case '\\': output += "\\\\"; break;
            case '"': output += "\\\""; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (ch < 0x20) {
                    static constexpr char kHex[] = "0123456789abcdef";
                    output += "\\u00";
                    output.push_back(kHex[(ch >> 4) & 0x0f]);
                    output.push_back(kHex[ch & 0x0f]);
                } else {
                    output.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return output;
}

bool WriteAll(int fd, std::string_view content) {
    std::size_t written_total = 0;
    while (written_total < content.size()) {
        const auto chunk = ::write(fd, content.data() + written_total,
                                   content.size() - written_total);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (chunk == 0) {
            return false;
        }
        written_total += static_cast<std::size_t>(chunk);
    }
    return true;
}

class JsonReader {
public:
    explicit JsonReader(std::string_view input) : input_(input) {}

    std::optional<StateFields> ParseObject() {
        StateFields fields;
        SkipWhitespace();
        if (!Consume('{')) {
            return std::nullopt;
        }
        SkipWhitespace();
        if (Consume('}')) {
            return fields;
        }

        while (true) {
            auto key = ParseString();
            if (!key) {
                return std::nullopt;
            }
            SkipWhitespace();
            if (!Consume(':')) {
                return std::nullopt;
            }
            SkipWhitespace();
            auto value = ParseString();
            if (!value) {
                return std::nullopt;
            }
            fields.emplace(std::move(*key), std::move(*value));
            SkipWhitespace();
            if (Consume('}')) {
                break;
            }
            if (!Consume(',')) {
                return std::nullopt;
            }
            SkipWhitespace();
        }

        SkipWhitespace();
        if (!AtEnd()) {
            return std::nullopt;
        }
        return fields;
    }

private:
    void SkipWhitespace() {
        while (!AtEnd() && std::isspace(static_cast<unsigned char>(input_[pos_]))) {
            ++pos_;
        }
    }

    bool Consume(char expected) {
        if (AtEnd() || input_[pos_] != expected) {
            return false;
        }
        ++pos_;
        return true;
    }

    bool AtEnd() const {
        return pos_ >= input_.size();
    }

    std::optional<std::string> ParseString() {
        if (!Consume('"')) {
            return std::nullopt;
        }

        std::string output;
        while (!AtEnd()) {
            char ch = input_[pos_++];
            if (ch == '"') {
                return output;
            }
            if (ch != '\\') {
                output.push_back(ch);
                continue;
            }
            if (AtEnd()) {
                return std::nullopt;
            }
            char escaped = input_[pos_++];
            switch (escaped) {
                case '\\': output.push_back('\\'); break;
                case '"': output.push_back('"'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u': {
                    if (pos_ + 4 > input_.size()) {
                        return std::nullopt;
                    }
                    unsigned value = 0;
                    for (int i = 0; i < 4; ++i) {
                        char hex = input_[pos_++];
                        value <<= 4;
                        if (hex >= '0' && hex <= '9') {
                            value |= static_cast<unsigned>(hex - '0');
                        } else if (hex >= 'a' && hex <= 'f') {
                            value |= static_cast<unsigned>(hex - 'a' + 10);
                        } else if (hex >= 'A' && hex <= 'F') {
                            value |= static_cast<unsigned>(hex - 'A' + 10);
                        } else {
                            return std::nullopt;
                        }
                    }
                    if (value <= 0x7f) {
                        output.push_back(static_cast<char>(value));
                    } else {
                        output.push_back('?');
                    }
                    break;
                }
                default:
                    return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::string_view input_;
    std::size_t pos_ = 0;
};

}  // namespace

StateStore::StateStore(std::filesystem::path path) : path_(std::move(path)) {}

const std::filesystem::path& StateStore::path() const noexcept {
    return path_;
}

bool StateStore::Write(const StateFields& fields) const {
    if (path_.empty()) {
        return false;
    }

    const auto parent = path_.parent_path();
    std::error_code ec;
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }

    const auto temp_template_path = path_.parent_path() / (path_.filename().string() + ".XXXXXX");
    std::string temp_template = temp_template_path.string();
    temp_template.push_back('\0');
    const int temp_fd_raw = ::mkstemp(temp_template.data());
    if (temp_fd_raw < 0) {
        return false;
    }

    ScopedFd temp_fd(temp_fd_raw);
    const std::filesystem::path temp_path(temp_template.c_str());

    const std::string content = [&fields] {
        std::string json = "{";
        bool first = true;
        for (const auto& entry : fields) {
            if (!first) {
                json.push_back(',');
            }
            first = false;
            json.push_back('"');
            json += EscapeJsonString(entry.first);
            json += "\":";
            json.push_back('"');
            json += EscapeJsonString(entry.second);
            json.push_back('"');
        }
        json.push_back('}');
        return json;
    }();

    if (!WriteAll(temp_fd.get(), content)) {
        std::filesystem::remove(temp_path, ec);
        return false;
    }
    if (::fsync(temp_fd.get()) != 0) {
        std::filesystem::remove(temp_path, ec);
        return false;
    }

    temp_fd.reset();
    ec.clear();
    std::filesystem::rename(temp_path, path_, ec);
    if (ec) {
        std::filesystem::remove(temp_path, ec);
        return false;
    }
    return true;
}

std::optional<StateFields> StateStore::Read() const {
    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const std::string content = buffer.str();
    JsonReader reader(content);
    return reader.ParseObject();
}

bool StateStore::Remove() const {
    std::error_code ec;
    const auto exists = std::filesystem::exists(path_, ec);
    if (ec) {
        return false;
    }
    if (!exists) {
        return true;
    }
    return std::filesystem::remove(path_, ec);
}

}  // namespace inline_proxy
