#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza_x64.hpp>

using namespace xendiza;
using namespace xendiza::detail;

template <size_t N>
static DecodedInstruction Disasm(const std::array<uint8_t, N>& buf)
{
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), N));
}

TEST(X87OpcodeTest, D8_mem_FADD_m32fp)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD8, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D8_reg_FADD_st0_sti)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD8, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_mem_FLD_m32fp)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_reg_FLD_sti)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_reg_FCHS)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCHS);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_reg_FNOP)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0xD0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNOP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_mem_FLDENV)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLDENV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, D9_mem_FNSTENV)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNSTENV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, DB_mem_FLD_m80fp)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xDB, 0x28});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, DD_mem_FRSTOR)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xDD, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FRSTOR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, DD_mem_FSAVE)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xDD, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FSAVE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, DF_mem_FBLD_and_FBSTP)
{
    auto rbld = Disasm(std::array<uint8_t, 2>{0xDF, 0x20});
    EXPECT_EQ(rbld.instrId.opcode, OpcodeId::FBLD);
    EXPECT_EQ(rbld.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(rbld.length, 2);

    auto rbstp = Disasm(std::array<uint8_t, 2>{0xDF, 0x30});
    EXPECT_EQ(rbstp.instrId.opcode, OpcodeId::FBSTP);
    EXPECT_EQ(rbstp.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(rbstp.length, 2);
}

TEST(X87OpcodeTest, DF_reg_FNSTSW_ax)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xDF, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNSTSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.length, 2);
}

TEST(X87OpcodeTest, ReservedFormReturnsUndefined)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xD9, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X87OpcodeTest, InsufficientBuffer)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X87OpcodeTest, FWAITAndFNInitAreDistinct)
{
    auto wait_only = Disasm(std::array<uint8_t, 1>{0x9B});
    EXPECT_EQ(wait_only.instrId.opcode, OpcodeId::FWAIT);
    EXPECT_EQ(wait_only.length, 1);

    auto fninit = Disasm(std::array<uint8_t, 2>{0xDB, 0xE3});
    EXPECT_EQ(fninit.instrId.opcode, OpcodeId::FNINIT);
    EXPECT_EQ(fninit.length, 2);

    auto wait_then_fninit = Disasm(std::array<uint8_t, 3>{0x9B, 0xDB, 0xE3});
    EXPECT_EQ(wait_then_fninit.instrId.opcode, OpcodeId::FWAIT);
    EXPECT_EQ(wait_then_fninit.length, 1);
}

