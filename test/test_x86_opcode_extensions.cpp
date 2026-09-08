// test_x86_opcode_extensions.cpp
// Unit tests for the 1-byte opcode-extension groups dispatched via case 0xEE
// in xendiza_x86.cpp (Groups 1-6: 0x80/0x81/0x83/0xC0/0xC1/0xD0-D3/0xC6/0xC7/
// 0xF6/0xF7/0xFE/0xFF/0x8F), plus 0x69/0x6B IMUL three-operand forms and the
// 0x82 always-undefined path. These exercise the previously-untested (in
// 32-bit mode) GetInstructionDescriptor_opcode_extension_* shared helpers and
// the FF /2,/4,/6 r64->r32 normalization chain.
//
// All tests use the public xendiza::Disasm<32> entry point. 32-bit mode has no
// REX prefix, so all REX.W/REX.B scenarios from the x64 counterpart are absent;
// 0x66 (operand-size) shrinks r32->r16 and imm32->imm16 (subtracting 2 from
// length), while 8-bit forms (Group 1 r/m8, 0xC0, 0xD0/0xD2, 0xF6, 0xFE) are
// unaffected by 0x66.

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

// =============================================================================
// Group 1: 0x80  r/m8, imm8  (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP via /0../7)
// 8-bit operands are unaffected by 0x66.
// =============================================================================

TEST(X86OpcodeExtTest, Grp1_0x80_all_reg_fields_r8_imm8)
{
    const OpcodeId expected[] = {
        OpcodeId::ADD, OpcodeId::OR,  OpcodeId::ADC, OpcodeId::SBB,
        OpcodeId::AND, OpcodeId::SUB, OpcodeId::XOR, OpcodeId::CMP,
    };
    for (uint8_t reg = 0; reg < 8; ++reg) {
        // modrm = mod=11 reg=reg rm=000 -> r8, imm8
        const auto modrm = static_cast<uint8_t>(0xC0 | (reg << 3));
        auto result = Disasm32(std::array<uint8_t, 3>{0x80, modrm, 0x01});
        EXPECT_EQ(result.instrId.opcode, expected[reg]) << "reg=" << (int)reg;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
        EXPECT_EQ(result.instrId.operand_count, 2);
        EXPECT_EQ(result.length, 3);
    }
}

TEST(X86OpcodeExtTest, Grp1_0x80_mem_form_m8_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x80, 0x00, 0x01}); // mod=00 reg=0 rm=0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp1_0x80_66h_does_not_affect_8bit)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x80, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86OpcodeExtTest, Grp1_0x80_SIB_base5_disp32_length)
{
    // 80 0C 85 78 56 34 12 05  ->  OR byte [eax*4+disp32], 0x05 (reg=1)
    // modrm=0x0C: mod=00 reg=1(OR) rm=100(SIB); SIB=0x85 base=5 -> disp32
    auto result = Disasm32(std::array<uint8_t, 8>{0x80, 0x0C, 0x85, 0x78, 0x56, 0x34, 0x12, 0x05});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8); // base!=4 -> m8
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 8);
}

// =============================================================================
// Group 1: 0x81  r/m32, imm32  -> r16, imm16 under 0x66 (length -2)
// =============================================================================

TEST(X86OpcodeExtTest, Grp1_0x81_r32_imm32_reg_form)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0x81, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, Grp1_0x81_mem_form_m32_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0x81, 0x08, 0x01, 0x00, 0x00, 0x00}); // mod=00 reg=1 rm=0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, Grp1_0x81_66h_shrinks_to_r16_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0x81, 0xC0, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// Group 1: 0x82  always UNDEFINED (the shared helper hard-codes the error)
// =============================================================================

TEST(X86OpcodeExtTest, Grp1_0x82_always_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x82, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// Group 1: 0x83  r/m32, imm8  (sign-extended)
// =============================================================================

TEST(X86OpcodeExtTest, Grp1_0x83_r32_imm8_reg_form)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x83, 0xC0, 0x01}); // /0 ADD
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp1_0x83_mem_form_m32_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x83, 0x30, 0x02}); // mod=00 reg=6 rm=0 XOR
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XOR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp1_0x83_66h_shrinks_to_r16_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x83, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Group 2: 0xC0  r/m8, imm8  (shift/rotate group)
// =============================================================================

TEST(X86OpcodeExtTest, Grp2_0xC0_all_reg_fields_r8_imm8)
{
    const OpcodeId expected[] = {
        OpcodeId::ROL, OpcodeId::ROR, OpcodeId::RCL, OpcodeId::RCR,
        OpcodeId::SHL, OpcodeId::SHR, OpcodeId::SAL, OpcodeId::SAR,
    };
    for (uint8_t reg = 0; reg < 8; ++reg) {
        const auto modrm = static_cast<uint8_t>(0xC0 | (reg << 3));
        auto result = Disasm32(std::array<uint8_t, 3>{0xC0, modrm, 0x04});
        EXPECT_EQ(result.instrId.opcode, expected[reg]) << "reg=" << (int)reg;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
        EXPECT_EQ(result.length, 3);
    }
}

TEST(X86OpcodeExtTest, Grp2_0xC0_mem_form_m8_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC0, 0x00, 0x04}); // /0 ROL
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// Group 2: 0xC1  r/m32, imm8  (shift/rotate group; 0x66 -> r16)
// =============================================================================

TEST(X86OpcodeExtTest, Grp2_0xC1_r32_imm8_reg_form)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC1, 0xE0, 0x04}); // /4 SHL
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp2_0xC1_mem_form_m32_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC1, 0x28, 0x02}); // /5 SHR
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp2_0xC1_66h_shrinks_to_r16_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0xC1, 0xE0, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Group 3: 0xD0/0xD1  r/m8,1 / r/m32,1  (shift by literal 1)
//           0xD2/0xD3  r/m8,CL / r/m32,CL (shift by CL)
// =============================================================================

TEST(X86OpcodeExtTest, Grp3_0xD0_r8_lit1)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD0, 0xC0}); // /0 ROL r8, 1
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp3_0xD0_mem_form_m8_lit1)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD0, 0x00}); // /0 ROL m8, 1
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp3_0xD1_r32_lit1)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD1, 0xE8}); // /5 SHR r32, 1
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp3_0xD1_66h_shrinks_to_r16_lit1)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x66, 0xD1, 0xE8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::lit1);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp3_0xD2_r8_cl)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD2, 0xC8}); // /1 ROR r8, cl
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ROR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::cl);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp3_0xD3_r32_cl)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD3, 0xF8}); // /7 SAR r32, cl
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::cl);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Group 4: 0xC6  MOV r/m8, imm8  (only /0 valid)
//           0xC7  MOV r/m32, imm32 (only /0 valid; 0x66 -> r16, imm16)
// =============================================================================

TEST(X86OpcodeExtTest, Grp4_0xC6_r8_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC6, 0xC0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp4_0xC6_mem_form_m8_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC6, 0x00, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp4_0xC6_invalid_slash1_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xC6, 0xC8, 0x42}); // /1 invalid
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86OpcodeExtTest, Grp4_0xC7_r32_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, Grp4_0xC7_mem_form_m32_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0xC7, 0x00, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, Grp4_0xC7_66h_shrinks_to_r16_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0xC7, 0xC0, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// Group 5: 0xF6  unary Eb group (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
//           TEST (/0,/1) carries an imm8 second operand.
// =============================================================================

TEST(X86OpcodeExtTest, Grp5_0xF6_TEST_r8_imm8_extra_imm)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xF6, 0xC0, 0xFF}); // /0 TEST r8, imm8
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp5_0xF6_NOT_r8_no_extra_imm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xF6, 0xD0}); // /2 NOT r8
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp5_0xF6_all_non_test_reg_fields_no_imm)
{
    const OpcodeId expected[] = {
        OpcodeId::NOT, OpcodeId::NEG, OpcodeId::MUL,
        OpcodeId::IMUL, OpcodeId::DIV, OpcodeId::IDIV,
    };
    for (uint8_t reg = 2; reg <= 7; ++reg) {
        const auto modrm = static_cast<uint8_t>(0xC0 | (reg << 3));
        auto result = Disasm32(std::array<uint8_t, 2>{0xF6, modrm});
        EXPECT_EQ(result.instrId.opcode, expected[reg - 2]) << "reg=" << (int)reg;
        EXPECT_EQ(result.instrId.operand_count, 1);
        EXPECT_EQ(result.length, 2);
    }
}

TEST(X86OpcodeExtTest, Grp5_0xF6_mem_form_m8)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xF6, 0x18}); // /3 NEG m8
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NEG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Group 5: 0xF7  unary Ev group (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
//           TEST (/0,/1) carries an imm32 (-> imm16 under 0x66, length -2).
// =============================================================================

TEST(X86OpcodeExtTest, Grp5_0xF7_TEST_r32_imm32_extra_imm)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0xF7, 0xC0, 0xFF, 0x00, 0x00, 0x00}); // /0 TEST r32, imm32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, Grp5_0xF7_NOT_r32_no_extra_imm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xF7, 0xD0}); // /2 NOT r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp5_0xF7_66h_shrinks_non_test_to_r16)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x66, 0xF7, 0xD0}); // /2 NOT r16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp5_0xF7_66h_TEST_shrinks_to_r16_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0xF7, 0xC0, 0xFF, 0x00}); // TEST r16, imm16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// Group 6: 0xFE  INC/DEC Eb only (only /0,/1 valid)
// =============================================================================

TEST(X86OpcodeExtTest, Grp6_0xFE_INC_r8)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFE, 0xC0}); // /0 INC r8
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFE_DEC_mem_form_m8)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFE, 0x08}); // /1 DEC m8
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFE_invalid_slash2_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFE, 0x10}); // /2 invalid
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// Group 6: 0xFF  INC/DEC/CALL/JMP/PUSH Ev group
//           /2 (CALL), /4 (JMP), /6 (PUSH) are rewritten to r64/m64 by the
//           shared helper. In 32-bit mode the register form is downgraded to
//           r32 by NormalizeOperandSize32 and the memory form to m32 by the
//           FF/8F m64->m32 rewrite in the 0xEE handler.
// =============================================================================

TEST(X86OpcodeExtTest, Grp6_0xFF_INC_r32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0xC0}); // /0 INC r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_DEC_mem_form_m32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0x08}); // /1 DEC m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_CALL_r32_normalized)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0xD0}); // /2 CALL r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_CALL_mem_form_m32)
{
    // FF /2 CALL memory form: the shared helper emits the long-mode-default
    // m64; in 32-bit mode it is downgraded to m32.
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0x10}); // /2 CALL m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_CALL_mem_SIB_base4_esp_is_stack_m32)
{
    // FF 14 24 -> CALL [esp] (/2). SIB base=100 (ESP) selects the stack form;
    // the shared 0xFF helper forces m64, so the decode site recovers the stack
    // marker and the 32-bit downgrade yields stack_m32.
    auto result = Disasm32(std::array<uint8_t, 3>{0xFF, 0x14, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_PUSH_mem_SIB_base4_esp_is_stack_m32)
{
    // FF 34 24 -> PUSH [esp] (/6). ESP base => stack_m32.
    auto result = Disasm32(std::array<uint8_t, 3>{0xFF, 0x34, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_CALL_mem_SIB_base5_stays_m32)
{
    // FF 14 85 + disp32 -> CALL [eax*4 + disp32]. SIB base=101 (no base reg),
    // not the stack form: must stay m32.
    auto result = Disasm32(std::array<uint8_t, 7>{0xFF, 0x14, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 7);
}

TEST(X86OpcodeExtTest, POP_0x8F_mem_SIB_base4_esp_is_stack_m32)
{
    // 8F 04 24 -> POP [esp] (/0). ESP base => stack_m32.
    auto result = Disasm32(std::array<uint8_t, 3>{0x8F, 0x04, 0x24});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::stack_m32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_invalid_slash3_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0x18}); // /3 invalid
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86OpcodeExtTest, Grp6_0xFF_JMP_r32_normalized)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0xE0}); // /4 JMP r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_PUSH_mem_form_m32)
{
    // FF /6 PUSH memory form: m64 long-mode default downgraded to m32 in
    // 32-bit mode (same rewrite as CALL /2 above).
    auto result = Disasm32(std::array<uint8_t, 2>{0xFF, 0x30}); // /6 PUSH m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, Grp6_0xFF_invalid_slash5_and_slash7_undefined)
{
    for (const auto modrm : std::array<uint8_t, 2>{0x28 /* /3 */, 0x38 /* /7 */}) {
        auto result = Disasm32(std::array<uint8_t, 2>{0xFF, modrm});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE) << "modrm=" << std::hex << (int)modrm;
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

// =============================================================================
// 0x8F  POP r/m  (only /0 valid)
//       Register form r64 is downgraded to r32 by NormalizeOperandSize32, and
//       the memory form m64 to m32 by the FF/8F rewrite in the 0xEE handler.
// =============================================================================

TEST(X86OpcodeExtTest, POP_0x8F_slash0_r32_normalized)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x8F, 0xC0}); // /0 POP r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, POP_0x8F_slash0_mem_form_m32)
{
    // 8F /0 POP memory form: the shared 0x8F helper returns the long-mode
    // m64, downgraded to m32 in 32-bit mode.
    auto result = Disasm32(std::array<uint8_t, 2>{0x8F, 0x00}); // /0 POP m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86OpcodeExtTest, POP_0x8F_invalid_slash1_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x8F, 0x08}); // /1 invalid
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// IMUL three-operand forms (0x69 imm32 / 0x6B imm8), dispatched via
// DecodeModrmWithImmediate with kOperandFormTable_Gv_Ev.
// =============================================================================

TEST(X86OpcodeExtTest, IMUL_0x69_r32_r32_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0x69, 0xC1, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm32);
    EXPECT_EQ(result.instrId.operand_count, 3);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, IMUL_0x69_mem_form_m32_imm32)
{
    auto result = Disasm32(std::array<uint8_t, 6>{0x69, 0x01, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OpcodeExtTest, IMUL_0x6B_r32_r32_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x6B, 0xC1, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.instrId.operand_count, 3);
    EXPECT_EQ(result.length, 3);
}

TEST(X86OpcodeExtTest, IMUL_0x69_66h_shrinks_to_r16_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0x69, 0xC1, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm16);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// Segment override prefix + extension-group composite memory operand.
// InjectSegmentForMemory should rewrite the first memory operand to a
// segment-prefixed composite (e.g. cs_m8) for the Group 1 r/m8 form.
// =============================================================================

TEST(X86OpcodeExtTest, Grp1_0x80_with_CS_prefix_composite_m8)
{
    // 2E 80 00 01 -> ADD cs:[eax], 0x01 (CS=0x2E, mod=00 reg=0 rm=0)
    auto result = Disasm32(std::array<uint8_t, 4>{0x2E, 0x80, 0x00, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::cs_m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86OpcodeExtTest, Grp1_0x81_with_FS_prefix_composite_m32)
{
    // 64 81 00 01 00 00 00 -> ADD fs:[eax], imm32
    auto result = Disasm32(std::array<uint8_t, 7>{0x64, 0x81, 0x00, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs_m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 7);
}

// =============================================================================
// Buffer-too-short error paths
// =============================================================================

TEST(X86OpcodeExtTest, BufferTooShort_missing_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x80});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86OpcodeExtTest, BufferTooShort_missing_imm)
{
    // case 0xEE for the immediate-carrying groups (0x80/81/83/C0/C1/C6/C7/F6/F7)
    // verifies the trailing immediate bytes are within the buffer before
    // reporting success. {0x80, 0xC0} needs one more imm8 byte, so the decode
    // must report INSUFFICIENT_BUFFER rather than a length-3 success.
    auto result = Disasm32(std::array<uint8_t, 2>{0x80, 0xC0});
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86OpcodeExtTest, BufferTooShort_SIB_missing_byte)
{
    // modrm=0x04 (SIB), but buffer ends right after modrm
    auto result = Disasm32(std::array<uint8_t, 2>{0x80, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}
