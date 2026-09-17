// test_x64_prefixes.cpp
// 64-bit mode prefix handling: repeated legacy prefixes, REX ordering
// (invalidated when a legacy prefix follows), and the 15-byte total
// instruction-length limit. Semantics follow Zydis's prefix collector.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza_x64.hpp>

using namespace xendiza;
using namespace xendiza::detail;

// Helper: disassemble a byte array
template <size_t N>
static DecodedInstruction Disasm(const std::array<uint8_t, N>& buf)
{
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), N));
}

namespace {

constexpr uint8_t UNDEFINED = static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION);

} // namespace

// =============================================================================
// 15-byte total instruction-length limit (multi-prefix NOP boundary)
// =============================================================================

// 66 66 66 66 66 66 66 0F 1F 84 00 00 00 00 00: seven 66h prefixes plus the
// 9-byte nop form (0F 1F /0 with SIB + disp32) = exactly 15 bytes, the
// architectural maximum. Emitted by GAS .p2align padding.
TEST(X64PrefixTest, MultiPrefix_15ByteNop_66x7)
{
    auto result = Disasm(std::array<uint8_t, 15>{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 15);
}

// Canonical GAS 15-byte nop: six 66h prefixes + a CS segment prefix.
TEST(X64PrefixTest, Gas15ByteNop_66x6_CS)
{
    auto result = Disasm(std::array<uint8_t, 15>{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E,
                                                 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 15);
}

// One more 66h prefix pushes the total to 16 bytes: over the architectural
// limit, so the decode must fail the way a CPU #GPs on such an instruction.
TEST(X64PrefixTest, Over15Byte_66x8_rejected)
{
    auto result = Disasm(std::array<uint8_t, 16>{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, UNDEFINED);
}

// 14 prefix bytes + 1 opcode byte = exactly 15, still decodable.
TEST(X64PrefixTest, FourteenPrefixes_15ByteNop)
{
    auto result = Disasm(std::array<uint8_t, 15>{
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 15);
}

// 15 prefix bytes leave no room for an opcode: rejected by ProcessPrefix.
TEST(X64PrefixTest, FifteenPrefixes_no_opcode_rejected)
{
    auto result = Disasm(std::array<uint8_t, 15>{
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, UNDEFINED);
}

// Segment overrides have no duplicate check; 9 of them plus the 9-byte nop
// would total 17 bytes - caught by the total-length limit, not the prefix loop.
TEST(X64PrefixTest, Over15_SegPrefixes_rejected)
{
    auto result = Disasm(std::array<uint8_t, 17>{0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
                                                 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, UNDEFINED);
}

// =============================================================================
// Repeated legacy prefixes: accepted, state bytes last-one-wins
// =============================================================================

TEST(X64PrefixTest, Duplicate_66_ok)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x66, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X64PrefixTest, Duplicate_REX_last_wins)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x48, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X64PrefixTest, Duplicate_LOCK_ok)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF0, 0xF0, 0x01, 0x00}); // ADD m32,r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 4);
}

TEST(X64PrefixTest, Duplicate_REP_last_wins)
{
    // F3 then F3: rep_byte stays REPE -> x64 maps F3 90 to PAUSE.
    auto result = Disasm(std::array<uint8_t, 3>{0xF3, 0xF3, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PAUSE);
    EXPECT_EQ(result.length, 3);
}

TEST(X64PrefixTest, Mixed_66_67_ok)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x67, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X64PrefixTest, Two_seg_prefixes_last_wins)
{
    // 2E (CS) then 64 (FS) on ADD: fs composites in 64-bit mode, cs does not.
    auto result = Disasm(std::array<uint8_t, 4>{0x2E, 0x64, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs_m32);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// REX ordering: a REX followed by any legacy prefix is invalidated entirely
// (bits dropped, instruction still decodes) - Zydis semantics.
// =============================================================================

TEST(X64PrefixTest, REX_invalidated_by_later_prefix)
{
    // 48 66 C7 C0 34 12: REX.W is dropped by the later 66h, so this decodes as
    // 66 C7 C0 = MOV ax, 0x1234 (r16/imm16), not MOV rax, sign-extended imm32.
    auto result = Disasm(std::array<uint8_t, 6>{0x48, 0x66, 0xC7, 0xC0, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 6);
}

TEST(X64PrefixTest, REX_invalidated_simple)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x66, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

// REX followed by the 0F escape is fine: REX stays effective.
TEST(X64PrefixTest, REX_before_0F_escape_ok)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x1F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// 0F 1F /0 length: mandatory disp32 when mod=00, r/m=100, SIB.base=101
// =============================================================================

TEST(X64PrefixTest, NOP_0F1F_SIB_base5_disp32_length)
{
    // 0F 1F 04 25 disp32: nop DWORD PTR ds:0x12345678 (8 bytes).
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0x1F, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 8);
}

TEST(X64PrefixTest, NOP_0F1F_SIB_mod10_no_extra_disp)
{
    // 0F 1F 84 00 disp32: mod=10 already carries disp32 in the length table;
    // the base=101 fixup must not fire here (8 bytes, not 12).
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0x1F, 0x84, 0x00, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 8);
}
