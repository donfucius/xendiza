// test_opcode_extensions.cpp
// Tests for instructions with opcode extensions (ModR/M.reg dispatch) and prefix handling.

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

// =============================================================================
// Prefix handling
// =============================================================================

TEST(OpcodeExtTest, REX_W_prefix_is_consumed)
{
    // REX.W (0x48) + NOP (0x90): length = 2 (prefix + opcode)
    auto result = Disasm(std::array<uint8_t, 2>{0x48, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, Prefix66_is_consumed_before_NOP)
{
    // 0x66 + NOP: length = 2
    auto result = Disasm(std::array<uint8_t, 2>{0x66, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, REX_W_prefix_length_adds_to_ADD_modrm)
{
    // REX.W + ADD r/m8,r8 (0x00) + ModRM(mod=11): length = 1+1+1 = 3
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x00, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, Multiple_prefixes_REX_W_and_66)
{
    // 0x66 + REX.W (0x48) + NOP: length = 3
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x48, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// Group 1: 0x80 - r/m8, imm8 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP)
// =============================================================================

TEST(OpcodeExtTest, ADD_0x80_r8_imm8_reg_form)
{
    // 0x80 0xC0 0x01 → ADD al, 1  (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x80, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, OR_0x80_r8_imm8)
{
    // 0x80 0xC8 0x01 → OR al, 1  (mod=11 reg=001 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x80, 0xC8, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

TEST(OpcodeExtTest, AND_0x80_r8_imm8)
{
    // 0x80 0xE0 0xFF → AND al, 0xFF (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x80, 0xE0, 0xFF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::AND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

TEST(OpcodeExtTest, CMP_0x80_r8_imm8)
{
    // 0x80 0xF8 0x00 → CMP al, 0 (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x80, 0xF8, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

TEST(OpcodeExtTest, ADD_0x80_m8_imm8_mem_form)
{
    // 0x80 0x00 0x01 → ADD [rax], 1  (mod=00 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x80, 0x00, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// Group 1: 0x81 - r/m32, imm32
// =============================================================================

TEST(OpcodeExtTest, ADD_0x81_r32_imm32)
{
    // 0x81 0xC0 0x01 0x00 0x00 0x00 → ADD eax, 1 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 6>{0x81, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(OpcodeExtTest, SUB_0x81_r32_imm32)
{
    // 0x81 0xE8 0x10 0x00 0x00 0x00 → SUB eax, 16 (mod=11 reg=101 r/m=000)
    auto result = Disasm(std::array<uint8_t, 6>{0x81, 0xE8, 0x10, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
}

TEST(OpcodeExtTest, CMP_0x81_r32_imm32)
{
    // 0x81 0xF8 0x00 0x00 0x00 0x00 → CMP eax, 0 (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 6>{0x81, 0xF8, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
}

TEST(OpcodeExtTest, ADD_0x81_REX_W_prefix)
{
    // REX.W + 0x81 0xC0 0x01 0x00 0x00 0x00 → ADD rax, 1 (64-bit)
    auto result = Disasm(std::array<uint8_t, 7>{0x48, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 7);
}

// =============================================================================
// Group 1: 0x83 - r/m32, imm8
// =============================================================================

TEST(OpcodeExtTest, ADD_0x83_r32_imm8)
{
    // 0x83 0xC0 0x01 → ADD eax, 1 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x83, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, SUB_0x83_r32_imm8)
{
    // 0x83 0xEC 0x20 → SUB esp, 32 (mod=11 reg=101 r/m=100)
    auto result = Disasm(std::array<uint8_t, 3>{0x83, 0xEC, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, CMP_0x83_m32_imm8_mem_form)
{
    // 0x83 0x38 0x00 → CMP [rax], 0 (mod=00 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0x83, 0x38, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// Group 2: 0xC0 - Shift/Rotate r/m8, imm8
// =============================================================================

TEST(OpcodeExtTest, ROL_0xC0_r8_imm8)
{
    // 0xC0 0xC0 0x01 → ROL al, 1 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC0, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, SHL_0xC0_r8_imm8)
{
    // 0xC0 0xE0 0x02 → SHL al, 2 (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC0, 0xE0, 0x02});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

TEST(OpcodeExtTest, SAR_0xC0_r8_imm8)
{
    // 0xC0 0xF8 0x01 → SAR al, 1 (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC0, 0xF8, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

// =============================================================================
// Group 2: 0xC1 - Shift/Rotate r/m32, imm8
// =============================================================================

TEST(OpcodeExtTest, SHL_0xC1_r32_imm8)
{
    // 0xC1 0xE0 0x02 → SHL eax, 2 (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC1, 0xE0, 0x02});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, SAR_0xC1_r32_imm8)
{
    // 0xC1 0xF8 0x01 → SAR eax, 1 (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC1, 0xF8, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

TEST(OpcodeExtTest, SHR_0xC1_r32_imm8)
{
    // 0xC1 0xE8 0x08 → SHR eax, 8 (mod=11 reg=101 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC1, 0xE8, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
}

// =============================================================================
// Group 3: 0xD0/0xD1 - Shift/Rotate r/m, 1
// =============================================================================

TEST(OpcodeExtTest, ROL_0xD0_r8_lit1)
{
    // 0xD0 0xC0 → ROL al, 1 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD0, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, SHR_0xD0_r8_lit1)
{
    // 0xD0 0xE8 → SHR al, 1 (mod=11 reg=101 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD0, 0xE8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
}

TEST(OpcodeExtTest, SHL_0xD1_r32_lit1)
{
    // 0xD1 0xE0 → SHL eax, 1 (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD1, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, SAR_0xD1_r32_lit1)
{
    // 0xD1 0xF8 → SAR eax, 1 (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD1, 0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
}

// =============================================================================
// Group 3: 0xD2/0xD3 - Shift/Rotate r/m, CL
// =============================================================================

TEST(OpcodeExtTest, SHL_0xD2_r8_cl)
{
    // 0xD2 0xE0 → SHL al, cl (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD2, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::cl);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, SHR_0xD3_r32_cl)
{
    // 0xD3 0xE8 → SHR eax, cl (mod=11 reg=101 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xD3, 0xE8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::cl);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Group 4: 0xC6/0xC7 - MOV r/m, immediate
// =============================================================================

TEST(OpcodeExtTest, MOV_0xC6_r8_imm8)
{
    // 0xC6 0xC0 0x42 → MOV al, 0x42 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xC6, 0xC0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, REX_W_0xC6_MOV_r8_imm8_no_width_change)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0xC6, 0xC0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(OpcodeExtTest, Prefix66_0xC6_MOV_r8_imm8_no_width_change)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xC6, 0xC0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(OpcodeExtTest, REX_B_0xC6_MOV_r8_imm8_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x41, 0xC6, 0xC0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(OpcodeExtTest, MOV_0xC7_r32_imm32)
{
    // 0xC7 0xC0 0x42 0x00 0x00 0x00 → MOV eax, 0x42 (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 6>{0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

// =============================================================================
// Group 5: 0xF6/0xF7 - Unary Operations (TEST, NOT, NEG, MUL, IMUL, DIV, IDIV)
// =============================================================================

TEST(OpcodeExtTest, TEST_0xF6_r8_imm8)
{
    // 0xF6 0xC0 0xFF → TEST al, 0xFF (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 3>{0xF6, 0xC0, 0xFF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, NOT_0xF6_r8)
{
    // 0xF6 0xD0 → NOT al (mod=11 reg=010 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF6, 0xD0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOT);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, NEG_0xF6_r8)
{
    // 0xF6 0xD8 → NEG al (mod=11 reg=011 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF6, 0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NEG);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, MUL_0xF6_r8)
{
    // 0xF6 0xE0 → MUL al (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF6, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MUL);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, DIV_0xF6_r8)
{
    // 0xF6 0xF0 → DIV al (mod=11 reg=110 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF6, 0xF0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DIV);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, IDIV_0xF6_r8)
{
    // 0xF6 0xF8 → IDIV al (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF6, 0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IDIV);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, TEST_0xF7_r32_imm32)
{
    // 0xF7 0xC0 0xFF 0x00 0x00 0x00 → TEST eax, 0xFF (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 6>{0xF7, 0xC0, 0xFF, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(OpcodeExtTest, MUL_0xF7_r32)
{
    // 0xF7 0xE0 → MUL eax (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF7, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MUL);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, IDIV_0xF7_r32)
{
    // 0xF7 0xF8 → IDIV eax (mod=11 reg=111 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xF7, 0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IDIV);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Group 6: 0xFE - INC/DEC r/m8
// =============================================================================

TEST(OpcodeExtTest, INC_0xFE_r8)
{
    // 0xFE 0xC0 → INC al (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFE, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, DEC_0xFE_r8)
{
    // 0xFE 0xC8 → DEC al (mod=11 reg=001 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFE, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Group 6: 0xFF - INC/DEC/CALL/JMP/PUSH r/m64
// =============================================================================

TEST(OpcodeExtTest, INC_0xFF_r32)
{
    // 0xFF 0xC0 → INC eax (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, DEC_0xFF_r32)
{
    // 0xFF 0xC8 → DEC eax (mod=11 reg=001 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, CALL_0xFF_r64)
{
    // 0xFF 0xD0 → CALL rax (mod=11 reg=010 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xD0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, CALL_0xFF_m64_mem_form)
{
    // 0xFF 0x10 → CALL [rax] (mod=00 reg=010 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, CALL_0xFF_m64_mem_SIB_base5_disp32)
{
    // 0xFF 0x14 0x85 + disp32 -> CALL [rax*4 + disp32]
    auto result = Disasm(std::array<uint8_t, 7>{0xFF, 0x14, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, CALL_0xFF_mem_SIB_base4_rsp_is_stack_m64)
{
    // 0xFF 0x14 0x24 -> CALL [rsp]. SIB base=100 (RSP) selects the stack form;
    // the shared 0xFF helper forces m64, so the decode site must recover
    // stack_m64 like every other RSP-base memory operand.
    auto result = Disasm(std::array<uint8_t, 3>{0xFF, 0x14, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, JMP_0xFF_mem_SIB_base4_rsp_is_stack_m64)
{
    // 0xFF 0x24 0x24 -> JMP [rsp] (/4). RSP base => stack_m64.
    auto result = Disasm(std::array<uint8_t, 3>{0xFF, 0x24, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, PUSH_0xFF_mem_SIB_base4_rsp_is_stack_m64)
{
    // 0xFF 0x34 0x24 -> PUSH [rsp] (/6). RSP base => stack_m64.
    auto result = Disasm(std::array<uint8_t, 3>{0xFF, 0x34, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, POP_0x8F_mem_SIB_base4_rsp_is_stack_m64)
{
    // 0x8F 0x04 0x24 -> POP [rsp] (/0). RSP base => stack_m64.
    auto result = Disasm(std::array<uint8_t, 3>{0x8F, 0x04, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, CALL_0xFF_REX_B_stays_abstract_and_length_consistent)
{
    // REX.B should be consumed but not force concrete register-id output in P2.
    auto result = Disasm(std::array<uint8_t, 3>{0x41, 0xFF, 0xD0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, JMP_0xFF_r64)
{
    // 0xFF 0xE0 → JMP rax (mod=11 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, JMP_0xFF_m64_mem_form)
{
    // 0xFF 0x20 → JMP [rax] (mod=00 reg=100 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, JMP_0xFF_m64_mem_SIB_base5_disp32)
{
    // 0xFF 0x24 0x85 + disp32 -> JMP [rax*4 + disp32]
    auto result = Disasm(std::array<uint8_t, 7>{0xFF, 0x24, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, JMP_0xFF_REX_B_stays_abstract_and_length_consistent)
{
    // REX.B should be consumed but not force concrete register-id output in P2.
    auto result = Disasm(std::array<uint8_t, 3>{0x41, 0xFF, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, PUSH_0xFF_r64)
{
    // 0xFF 0xF0 → PUSH rax (mod=11 reg=110 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xF0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, FF_slash3_is_invalid)
{
    // 0xFF /3 is reserved/undefined.
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(OpcodeExtTest, FF_slash5_is_invalid)
{
    // 0xFF /5 is reserved/undefined.
    auto result = Disasm(std::array<uint8_t, 2>{0xFF, 0xE8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

// =============================================================================
// Special: IMUL three-operand (0x69 / 0x6B)
// =============================================================================

TEST(OpcodeExtTest, IMUL_0x69_r32_rm32_imm32)
{
    // 0x69 ModRM(mod=11 reg=000 r/m=000) imm32
    // 0x69 0xC0 0x02 0x00 0x00 0x00 → IMUL eax, eax, 2
    auto result = Disasm(std::array<uint8_t, 6>{0x69, 0xC0, 0x02, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operand_count, 3);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(OpcodeExtTest, IMUL_0x6B_r32_rm32_imm8)
{
    // 0x6B 0xC0 0x08 → IMUL eax, eax, 8
    auto result = Disasm(std::array<uint8_t, 3>{0x6B, 0xC0, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operand_count, 3);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, IMUL_0x69_REX_W)
{
    // REX.W + 0x69 0xC0 0x02 0x00 0x00 0x00 → IMUL rax, rax, 2
    auto result = Disasm(std::array<uint8_t, 7>{0x48, 0x69, 0xC0, 0x02, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.length, 7);
}

// =============================================================================
// 8-bit instructions unaffected by REX.W or 0x66
// =============================================================================

TEST(OpcodeExtTest, ADD_0x80_r8_imm8_with_REXW_no_effect_on_opcode)
{
    // REX.W + 0x80 0xC0 0x01 - opcode is still 8-bit ADD
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x80, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(OpcodeExtTest, ADD_0x80_r8_imm8_with_Prefix66_no_effect_on_opcode)
{
    // 0x66 + 0x80 0xC0 0x01 - 0x80 is still 8-bit, 0x66 doesn't change it
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x80, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Memory operand with SIB and disp
// =============================================================================

TEST(OpcodeExtTest, ADD_0x81_mem_SIB_disp32)
{
    // 0x81 with ModRM mod=10 r/m=100 (SIB follows) + SIB + disp32 + imm32
    // ModRM = 0x84 (mod=10 reg=000 r/m=100), SIB = 0x24 (ss=00 idx=100 base=100 -> [rsp*1+rsp])
    // + 4 bytes disp32 + 4 bytes imm32 = 1+1+1+1+4+4 = 12 (opcode = 0x81)
    // total: prefix(0) + opcode(1) + modrm(1) + sib(1) + disp32(4) + imm32(4) = 11
    std::array<uint8_t, 11> buf = {0x81, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    auto result = Disasm(buf);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 11);
}

// =============================================================================
// POP via 0x8F /0
// =============================================================================

TEST(OpcodeExtTest, POP_0x8F_r64)
{
    // 0x8F 0xC0 → POP rax (mod=11 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0x8F, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, POP_0x8F_m64_mem_form)
{
    // 0x8F 0x00 → POP [rax] (mod=00 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0x8F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 2);
}

TEST(OpcodeExtTest, POP_0x8F_m64_mem_SIB_base5_disp32)
{
    // 0x8F 0x04 0x85 + disp32 -> POP [rax*4 + disp32]
    auto result = Disasm(std::array<uint8_t, 7>{0x8F, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, POP_0x8F_nonzero_extension_is_invalid)
{
    // 0x8F /1 is undefined; only /0 is valid for POP.
    auto result = Disasm(std::array<uint8_t, 2>{0x8F, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(OpcodeExtTest, Prefix66_0x8F_POP_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x8F, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.length, 3);
}

TEST(OpcodeExtTest, REX_W_0x8F_POP_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x8F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// REX.W / 66h operand-size effects on opcode extensions
// =============================================================================

// --- 0x81 (r/m32, imm32) ---

TEST(OpcodeExtTest, REX_W_0x81_ADD_r64_imm32)
{
    // REX.W (0x48) + 0x81 0xC0 0x01 0x00 0x00 0x00 → ADD rax, 1
    // REX.W promotes r32 → r64; imm32 stays 4 bytes (sign-extended)
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) + 4 (imm32) = 7
    auto result = Disasm(std::array<uint8_t, 7>{0x48, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, Prefix66_0x81_ADD_r16_imm16)
{
    // 0x66 + 0x81 0xC0 0x01 0x00 → ADD ax, 1
    // 66h promotes r32 → r16, imm32 → imm16 (encoding shrinks by 2)
    // length = 1 (0x66) + 1 (opcode) + 1 (ModRM) + 2 (imm16) = 5
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0x81, 0xC0, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

TEST(OpcodeExtTest, Prefix66_0x81_ADD_m16_imm16)
{
    // 0x66 + 0x81 0x00 0x01 0x00 → ADD word ptr [rax], 1
    // length = 1 (0x66) + 1 (opcode) + 1 (ModRM) + 2 (imm16) = 5
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0x81, 0x00, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// --- 0x83 (r/m32, imm8) ---

TEST(OpcodeExtTest, REX_W_0x83_ADD_r64_imm8)
{
    // REX.W + 0x83 0xC0 0x01 → ADD rax, 1
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) + 1 (imm8) = 4
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x83, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(OpcodeExtTest, Prefix66_0x83_ADD_r16_imm8)
{
    // 0x66 + 0x83 0xC0 0x01 → ADD ax, 1
    // 66h promotes r32 → r16; imm8 is unaffected
    // length = 1 (0x66) + 1 (opcode) + 1 (ModRM) + 1 (imm8) = 4
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x83, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

// --- 0xC1 (shifts, r/m32, imm8) ---

TEST(OpcodeExtTest, REX_W_0xC1_SHL_r64_imm8)
{
    // REX.W + 0xC1 0xE0 0x02 → SHL rax, 2  (mod=11 reg=100 r/m=000)
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) + 1 (imm8) = 4
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0xC1, 0xE0, 0x02});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

// --- 0xC7 (MOV r/m32, imm32) ---

TEST(OpcodeExtTest, REX_W_0xC7_MOV_r64_imm32)
{
    // REX.W + 0xC7 0xC0 0x01 0x00 0x00 0x00 → MOV rax, 1 (sign-extended imm32)
    // REX.W promotes r32 → r64; imm32 stays 4 bytes
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) + 4 (imm32) = 7
    auto result = Disasm(std::array<uint8_t, 7>{0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, Prefix66_0xC7_MOV_r16_imm16)
{
    // 0x66 + 0xC7 0xC0 0x01 0x00 → MOV ax, 1
    // 66h promotes r32 → r16, imm32 → imm16
    // length = 1 (0x66) + 1 (opcode) + 1 (ModRM) + 2 (imm16) = 5
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0xC7, 0xC0, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

TEST(OpcodeExtTest, REX_B_0xC7_MOV_r32_imm32_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 7>{0x41, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

// --- 0xF7 (TEST r/m32, imm32 variant) ---

TEST(OpcodeExtTest, REX_W_0xF7_TEST_r64_imm32)
{
    // REX.W + 0xF7 0xC0 0x01 0x00 0x00 0x00 → TEST rax, 1
    // REX.W promotes r32 → r64; imm32 stays 4 bytes
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) + 4 (imm32) = 7
    auto result = Disasm(std::array<uint8_t, 7>{0x48, 0xF7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

TEST(OpcodeExtTest, Prefix66_0xF7_TEST_r16_imm16)
{
    // 0x66 + 0xF7 0xC0 0x01 0x00 → TEST ax, 1
    // 66h promotes r32 → r16, imm32 → imm16
    // length = 1 (0x66) + 1 (opcode) + 1 (ModRM) + 2 (imm16) = 5
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0xF7, 0xC0, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// --- 0xFF (INC/DEC/CALL/JMP/PUSH r/m32) ---

TEST(OpcodeExtTest, REX_W_0xFF_INC_r64)
{
    // REX.W + 0xFF 0xC0 → INC rax (mod=11 reg=000 r/m=000)
    // REX.W promotes r32 → r64
    // length = 1 (REX) + 1 (opcode) + 1 (ModRM) = 3
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0xFF, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// Stack memory operands (effective-address base = RSP/ESP via SIB.base=100)
// =============================================================================

TEST(StackOperandTest, MOV_C6_stack_m8_imm8)
{
    // c6 84 24 8b 00 00 00 64 : mov byte [rsp+0x8b], 0x64
    auto result = Disasm(std::array<uint8_t, 8>{0xC6, 0x84, 0x24, 0x8B, 0x00, 0x00, 0x00, 0x64});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 8);
}

TEST(StackOperandTest, MOV_C7_stack_m32_imm32)
{
    // c7 04 24 11 22 33 44 : mov dword [rsp], 0x44332211
    auto result = Disasm(std::array<uint8_t, 7>{0xC7, 0x04, 0x24, 0x11, 0x22, 0x33, 0x44});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

TEST(StackOperandTest, MOV_C7_66_stack_m16)
{
    // 66 c7 04 24 11 22 : mov word [rsp], 0x2211
    auto result = Disasm(std::array<uint8_t, 6>{0x66, 0xC7, 0x04, 0x24, 0x11, 0x22});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
}

TEST(StackOperandTest, MOV_C7_REXW_stack_m64)
{
    // 48 c7 04 24 11 22 33 44 : mov qword [rsp], 0x44332211
    auto result = Disasm(std::array<uint8_t, 8>{0x48, 0xC7, 0x04, 0x24, 0x11, 0x22, 0x33, 0x44});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m64);
}

TEST(StackOperandTest, ADD_Eb_Gb_stack_m8)
{
    // 00 04 24 : add byte [rsp], al
    auto result = Disasm(std::array<uint8_t, 3>{0x00, 0x04, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m8);
}

TEST(StackOperandTest, MOV_Gv_Ev_stack_source_operand1)
{
    // 8b 04 24 : mov eax, dword [rsp]  (memory is the source operand)
    auto result = Disasm(std::array<uint8_t, 3>{0x8B, 0x04, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::stack_m32);
}

TEST(StackOperandTest, Group1_80_stack_m8)
{
    // 80 04 24 05 : add byte [rsp], 5
    auto result = Disasm(std::array<uint8_t, 4>{0x80, 0x04, 0x24, 0x05});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m8);
}

TEST(StackOperandTest, MOVZX_0FB6_stack_m8)
{
    // 0f b6 04 24 : movzx r32, byte [rsp]
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xB6, 0x04, 0x24});
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::stack_m8);
}

TEST(StackOperandTest, NonStack_no_sib_stays_m8)
{
    // c6 00 64 : mov byte [rax], 0x64  (no SIB → not a stack access)
    auto result = Disasm(std::array<uint8_t, 3>{0xC6, 0x00, 0x64});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
}

TEST(StackOperandTest, NonStack_sib_base5_disp32_stays_m8)
{
    // c6 04 25 00 00 00 00 64 : mov byte [disp32], 0x64  (SIB base=101, no base reg)
    auto result = Disasm(std::array<uint8_t, 8>{0xC6, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x64});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 8);
}

TEST(StackOperandTest, NonStack_register_form_unaffected)
{
    // c6 c0 64 : mov al, 0x64  (mod=11 register form)
    auto result = Disasm(std::array<uint8_t, 3>{0xC6, 0xC0, 0x64});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
}
