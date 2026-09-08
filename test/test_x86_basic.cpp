#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza.hpp>

using namespace xendiza;

template <size_t N>
static DecodedInstruction Disasm32(const std::array<uint8_t, N>& buf)
{
    return xendiza::Disasm<32>(gsl::span<const uint8_t>(buf.data(), N));
}

TEST(X86BasicTest, NOP_90)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 1);
}

TEST(X86BasicTest, ADD_01_modrm_reg)
{
    // 01 C8 -> ADD eax, ecx (abstract r32,r32)
    auto result = Disasm32(std::array<uint8_t, 2>{0x01, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86BasicTest, ADD_66_01_modrm_reg)
{
    // 66 01 C8 -> ADD ax, cx (abstract r16,r16)
    auto result = Disasm32(std::array<uint8_t, 3>{0x66, 0x01, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(X86BasicTest, MOV_B8_default_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0xB8, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86BasicTest, MOV_66_B8_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0xB8, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

TEST(X86BasicTest, MOV_A1_FS_moffs32)
{
    // 64 A1 20 00 00 00 -> mov eax, fs:[0x20]
    auto result = Disasm32(std::array<uint8_t, 6>{0x64, 0xA1, 0x20, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::fs_moffs32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86BasicTest, INC_41_ecx)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x41});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 1);
}

TEST(X86BasicTest, DEC_66_49_cx)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x66, 0x49});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 2);
}

TEST(X86BasicTest, EmptyBufferInsufficient)
{
    auto result = xendiza::Disasm<32>(gsl::span<const uint8_t>());
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

