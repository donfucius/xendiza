#ifndef XENDIZA_X86_HPP
#define XENDIZA_X86_HPP

#include "xendiza_common.hpp"

#include <bit>
#include <gsl/span>

namespace xendiza::detail {

enum class Prefix32 : uint8_t {
    LOCK = 0xF0,
    REPNE = 0xF2,
    REPE = 0xF3,

    CS_SEG = 0x2E,
    SS_SEG = 0x36,
    DS_SEG = 0x3E,
    ES_SEG = 0x26,
    FS_SEG = 0x64,
    GS_SEG = 0x65,

    OPR_SIZE = 0x66,
    ADDR_SIZE = 0x67,

    OPC_2BYTE = 0x0F,

    VEX_2BYTE = 0xC5,
    VEX_3BYTE = 0xC4,
    EVEX = 0x62,

    NONE = 0xFE,
    INVALID = 0xFF
};

struct HasPrefix32 {
    uint8_t has_66 : 1;
    uint8_t has_67 : 1;
    uint8_t has_seg : 1;
    uint8_t has_rex : 1; // kept for structural parity; always 0 for 32-bit mode
    uint8_t has_lock : 1;
    uint8_t has_rep : 1;
    uint8_t reserved : 2;

    explicit operator bool() const noexcept
    {
        return std::bit_cast<const uint8_t>(*this) != 0;
    }
};

struct PrefixInfo32 {
    uint8_t length = 0;
    HasPrefix32 has_prefix{};
    uint8_t seg_byte = 0;
    uint8_t rep_byte = 0;
};

class X86Traits {

    static auto ProcessPrefix(gsl::span<const uint8_t> buffer) noexcept -> std::pair<PrefixInfo32, ErrorCode>;
    static auto Decode2ByteOpcode(const PrefixInfo32& prefix_info, gsl::span<const uint8_t> buffer) noexcept
        -> DecodedInstruction;

public:
    static auto Disasm(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;
};

} // namespace xendiza::detail

#endif // XENDIZA_X86_HPP


