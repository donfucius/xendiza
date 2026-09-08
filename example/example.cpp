#include <xendiza/xendiza.hpp>

#include <filesystem>
#include <fstream>
#include <gsl/span>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

auto LoadFileBytes(const std::string& path) -> std::vector<uint8_t>
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

auto ReadTextFile(const std::filesystem::path& path) -> std::string
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

auto Trim(const std::string& s) -> std::string
{
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

auto ToLower(std::string s) -> std::string
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

auto ParseEnumNames(
    const std::string& text,
    const std::string& enum_start_marker,
    const std::string& fallback_prefix,
    const bool lowercase_names)
    -> std::unordered_map<uint16_t, std::string>
{
    std::unordered_map<uint16_t, std::string> result;
    const auto start = text.find(enum_start_marker);
    if (start == std::string::npos) {
        return result;
    }

    const auto open = text.find('{', start);
    const auto close = text.find("};", open);
    if (open == std::string::npos || close == std::string::npos) {
        return result;
    }

    uint32_t current = 0;
    bool has_current = false;
    std::istringstream lines(text.substr(open + 1, close - open - 1));
    std::string line;
    while (std::getline(lines, line)) {
        const auto cpos = line.find("//");
        if (cpos != std::string::npos) {
            line = line.substr(0, cpos);
        }

        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        // Split by comma to handle multiple enum entries on one line.
        std::istringstream tokens(line);
        std::string token;
        while (std::getline(tokens, token, ',')) {
            token = Trim(token);
            if (token.empty()) {
                continue;
            }

            std::string name;
            auto eq = token.find('=');
            if (eq != std::string::npos) {
                name = Trim(token.substr(0, eq));
                const auto value_text = Trim(token.substr(eq + 1));
                try {
                    current = static_cast<uint32_t>(std::stoul(value_text, nullptr, 0));
                    has_current = true;
                } catch (...) {
                    continue;
                }
            } else {
                name = token;
                if (!has_current) {
                    current = 0;
                    has_current = true;
                } else {
                    ++current;
                }
            }

            if (current <= 0xFFFFu) {
                result[static_cast<uint16_t>(current)] = lowercase_names ? ToLower(name) : name;
            }
        }
    }

    if (result.empty()) {
        result[0] = fallback_prefix + "0";
    }
    return result;
}

auto GetSourceRoot() -> std::filesystem::path
{
    // __FILE__ points to .../example/example.cpp in this repository.
    return std::filesystem::path(__FILE__).parent_path().parent_path();
}

auto BuildOpcodeMap() -> std::unordered_map<uint16_t, std::string>
{
    const auto text = ReadTextFile(GetSourceRoot() / "opcode_id.hpp");
    return ParseEnumNames(text, "enum class OpcodeId", "opcode_", true);
}

auto BuildOperandMap() -> std::unordered_map<uint16_t, std::string>
{
    const auto text = ReadTextFile(GetSourceRoot() / "instruction.hpp");
    return ParseEnumNames(text, "enum class Operand", "op_", false);
}

auto OpcodeToString(const xendiza::OpcodeId opcode) -> std::string
{
    static const auto kOpcodeMap = BuildOpcodeMap();
    const auto key = static_cast<uint16_t>(opcode);
    if (const auto it = kOpcodeMap.find(key); it != kOpcodeMap.end()) {
        return it->second;
    }
    return "opcode_" + std::to_string(key);
}

auto OperandToString(const xendiza::Operand operand) -> std::string
{
    if (operand == xendiza::Operand::noopr) {
        return {};
    }

    static const auto kOperandMap = BuildOperandMap();
    const auto key = static_cast<uint16_t>(operand);
    if (const auto it = kOperandMap.find(key); it != kOperandMap.end()) {
        return it->second;
    }

    return "op_" + std::to_string(key);
}

auto FormatInstruction(const xendiza::DecodedInstruction& di) -> std::string
{
    std::ostringstream oss;
    oss << OpcodeToString(di.instrId.opcode);

    bool first = true;
    for (uint8_t i = 0; i < di.instrId.operand_count; ++i) {
        const auto part = OperandToString(di.instrId.operands.operand[i]);
        if (part.empty()) {
            continue;
        }
        oss << (first ? " " : ", ") << part;
        first = false;
    }
    return oss.str();
}

void PrintDecoded(const size_t offset, const uint8_t* bytes, const xendiza::DecodedInstruction& di)
{
    std::ostringstream hex_bytes;
    for (uint8_t i = 0; i < di.length; ++i) {
        if (i > 0) hex_bytes << ' ';
        hex_bytes << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }

    std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << offset
              << "  " << std::left << std::setfill(' ') << std::setw(45) << hex_bytes.str()
              << "  len=" << std::right << std::dec << static_cast<int>(di.length)
              << "  " << FormatInstruction(di) << "\n";
}

template <size_t Bits>
void DecodeBuffer(const std::vector<uint8_t>& bytes, const std::string& mode_name)
{
    std::cout << "\n[" << mode_name << "]\n";

    size_t offset = 0;
    size_t decoded_count = 0;
    size_t error_count = 0;

    while (offset < bytes.size()) {
        const auto span = gsl::span<const uint8_t>(bytes.data() + offset, bytes.size() - offset);
        const auto di = xendiza::Disasm<Bits>(span);

        if (di.length >= 0xE0 || di.length == 0) {
            std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << offset
                      << "  decode_error=" << std::dec << static_cast<int>(di.length) << "\n";
            ++error_count;
            ++offset; // resync by 1 byte
            continue;
        }

        PrintDecoded(offset, bytes.data() + offset, di);
        ++decoded_count;
        offset += di.length;
    }

    std::cout << "decoded=" << decoded_count << " errors=" << error_count << "\n";
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <32|64> <shellcode_file_path>\n";
        return 1;
    }

    const std::string bits = argv[1];
    const std::string shellcode_path = argv[2];

    if (bits != "32" && bits != "64") {
        std::cerr << "invalid bitness: " << bits << " (expected 32 or 64)\n";
        return 1;
    }

    const auto bytes = LoadFileBytes(shellcode_path);
    if (bytes.empty()) {
        std::cerr << "failed to read shellcode file: " << shellcode_path << "\n";
        return 1;
    }

    std::cout << "disassembling: " << shellcode_path << "\n";
    std::cout << "bytes: " << bytes.size() << "\n";

    if (bits == "32") {
        DecodeBuffer<32>(bytes, "x86-32");
    } else {
        DecodeBuffer<64>(bytes, "x86-64");
    }
    return 0;
}
