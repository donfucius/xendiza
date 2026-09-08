// test_no_operands.cpp
// Tests for instructions without operands

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

// =============================================================================
// No-operand instructions
// =============================================================================

TEST(NoOperandTest, NOP_0x90)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, PAUSE_F3_90)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xF3, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PAUSE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(NoOperandTest, RET_0xC3)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, CLC_0xF8)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, STC_0xF9)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, CLI_0xFA)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLI);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, STI_0xFB)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STI);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, CLD_0xFC)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLD);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, STD_0xFD)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFD});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STD);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, PUSHFQ_0x9C)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x9C});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSHFQ);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, POPFQ_0x9D)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x9D});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POPFQ);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, CDWA_0x99)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x99});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CDQ);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, HLT_0xF4)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF4});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::HLT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(NoOperandTest, TwoByteOpcodeRDTSC_0x0F31)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x31});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDTSC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

