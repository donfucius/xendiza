// test_basic_instructions.cpp
// Tests for fundamental 1-byte opcode instructions (without opcode extensions).

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
// Arithmetic/Logic: ADD (0x00-0x05), OR (0x08-0x0D)
// =============================================================================

TEST(DisasmTest, ADD_0x00_modrm_mod11)
{
    // ADD r/m8, r8: opcode 0x00, ModRM = 0xC3 (mod=11 r/m=011 reg=000 → ADD bl, al)
    auto result = Disasm(std::array<uint8_t, 2>{0x00, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x00_modrm_mod00)
{
    // ADD [rax], al: 0x00 0x00 (mod=00 reg=000 r/m=000)
    auto result = Disasm(std::array<uint8_t, 2>{0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x01_modrm_mod11)
{
    // ADD r/m32, r32: 0x01 0xC8 (mod=11 reg=001 r/m=000 → ADD eax, ecx)
    auto result = Disasm(std::array<uint8_t, 2>{0x01, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x02_modrm_mod11)
{
    // ADD r8, r/m8: 0x02 0xC3 (mod=11 reg=000 r/m=011)
    auto result = Disasm(std::array<uint8_t, 2>{0x02, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x03_modrm_mod11)
{
    // ADD r32, r/m32: 0x03 0xC3
    auto result = Disasm(std::array<uint8_t, 2>{0x03, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x04_al_imm8)
{
    // ADD al, imm8: 0x04 0x42
    auto result = Disasm(std::array<uint8_t, 2>{0x04, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADD_0x05_eax_imm32)
{
    // ADD eax, imm32: 0x05 + 4 bytes
    auto result = Disasm(std::array<uint8_t, 5>{0x05, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, OR_0x08_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x08, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, OR_0x0D_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x0D, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// ADC, SBB (0x10-0x1D)
// =============================================================================

TEST(DisasmTest, ADC_0x10_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x10, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, ADC_0x14_al_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x14, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, SBB_0x18_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x18, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SBB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, SBB_0x1D_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x1D, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SBB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// AND, SUB (0x20-0x2D)
// =============================================================================

TEST(DisasmTest, AND_0x20_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x20, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::AND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, AND_0x25_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x25, 0xFF, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::AND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, SUB_0x28_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x28, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, SUB_0x2D_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x2D, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// XOR, CMP (0x30-0x3D)
// =============================================================================

TEST(DisasmTest, XOR_0x30_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x30, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XOR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, XOR_0x35_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x35, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XOR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, CMP_0x38_modrm_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x38, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, CMP_0x3D_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x3D, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// PUSH/POP r64 (0x50-0x5F)
// =============================================================================

TEST(DisasmTest, PUSH_all_regs)
{
    // 0x50-0x57 are all PUSH r64
    for (uint8_t opc = 0x50; opc <= 0x57; ++opc) {
        auto result = Disasm(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH) << "opcode=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(result.length, 1);
    }
}

TEST(DisasmTest, REX_B_PUSH_POP_boundaries_length_consistent)
{
    // REX.B should be consumed as a prefix; abstract operand class remains unchanged in P2.
    auto push_lo = Disasm(std::array<uint8_t, 2>{0x41, 0x50});
    EXPECT_EQ(push_lo.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(push_lo.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(push_lo.length, 2);

    auto push_hi = Disasm(std::array<uint8_t, 2>{0x41, 0x57});
    EXPECT_EQ(push_hi.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(push_hi.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(push_hi.length, 2);

    auto pop_lo = Disasm(std::array<uint8_t, 2>{0x41, 0x58});
    EXPECT_EQ(pop_lo.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(pop_lo.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(pop_lo.length, 2);

    auto pop_hi = Disasm(std::array<uint8_t, 2>{0x41, 0x5F});
    EXPECT_EQ(pop_hi.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(pop_hi.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(pop_hi.length, 2);
}

TEST(DisasmTest, MOV_GS_R64_M64_segment_operand)
{
    // 65 48 8B 04 25 60 00 00 00 -> mov rax, gs:[0x60] (abstract: r64, gs_m64)
    auto result = Disasm(std::array<uint8_t, 9>{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::gs_m64);
    EXPECT_EQ(result.length, 9);
}

TEST(DisasmTest, POP_all_regs)
{
    // 0x58-0x5F are all POP r64
    for (uint8_t opc = 0x58; opc <= 0x5F; ++opc) {
        auto result = Disasm(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::POP) << "opcode=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(result.length, 1);
    }
}

// =============================================================================
// PUSH imm32/imm8 (0x68, 0x6A)
// =============================================================================

TEST(DisasmTest, PUSH_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x68, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, PUSH_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x6A, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Jcc (0x70-0x7F): All conditional jumps
// =============================================================================

TEST(DisasmTest, Jcc_all_conditions)
{
    const OpcodeId expected[] = {
        OpcodeId::JO,  OpcodeId::JNO, OpcodeId::JB,  OpcodeId::JAE,
        OpcodeId::JZ,  OpcodeId::JNZ, OpcodeId::JBE, OpcodeId::JA,
        OpcodeId::JS,  OpcodeId::JNS, OpcodeId::JP,  OpcodeId::JNP,
        OpcodeId::JL,  OpcodeId::JGE, OpcodeId::JLE, OpcodeId::JG,
    };
    for (int i = 0; i < 16; ++i) {
        uint8_t opc = static_cast<uint8_t>(0x70 + i);
        auto result = Disasm(std::array<uint8_t, 2>{opc, 0x00});
        EXPECT_EQ(result.instrId.opcode, expected[i]) << "Jcc opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
        EXPECT_EQ(result.length, 2);
    }
}

// =============================================================================
// TEST, XCHG, MOV, LEA (0x84-0x8D)
// =============================================================================

TEST(DisasmTest, TEST_0x84_Eb_Gb_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x84, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, TEST_0x85_Ev_Gv_mod11)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x85, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, XCHG_0x86_Eb_Gb)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x86, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XCHG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, MOV_0x88_Eb_Gb)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x88, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
}

TEST(DisasmTest, REX_B_MOV_0x88_reg_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x88, 0xC0});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x88, 0xC0});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, REX_B_MOV_0x88_mem_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x88, 0x00});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x88, 0x00});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, MOV_0x89_Ev_Gv)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x89, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
}

TEST(DisasmTest, REX_B_MOV_0x89_reg_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x89, 0xC0});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x89, 0xC0});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, MOV_0x8B_Gv_Ev)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x8B, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
}

TEST(DisasmTest, REX_B_MOV_0x8A_reg_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x8A, 0xC0});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x8A, 0xC0});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, REX_B_MOV_0x8B_reg_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x8B, 0xC0});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x8B, 0xC0});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, MOV_0x8A_Gb_Eb)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x8A, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, MOV_0x8C_reg_form)
{
    // 0x8C 0xC8 → MOV eax, cs  (mod=11 reg=001 r/m=000 → CS→r16)
    auto result = Disasm(std::array<uint8_t, 2>{0x8C, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sreg);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, MOV_0x8C_mem_form)
{
    // 0x8C 0x08 → MOV [eax], cs  (mod=00 reg=001 r/m=000 → CS→m16)
    auto result = Disasm(std::array<uint8_t, 2>{0x8C, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sreg);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, MOV_0x8E_reg_form)
{
    // 0x8E 0xD8 → MOV ds, eax  (mod=11 reg=011=DS r/m=000 → r16→DS)
    auto result = Disasm(std::array<uint8_t, 2>{0x8E, 0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sreg);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, MOV_0x8E_mem_form)
{
    // 0x8E 0x18 → MOV ds, [eax]  (mod=00 reg=011=DS r/m=000 → m16→DS)
    auto result = Disasm(std::array<uint8_t, 2>{0x8E, 0x18});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count, 2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sreg);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m16);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, LEA_0x8D_Gv_M_mod01)
{
    // LEA with mod=01 (indirect+disp8): 0x8D 0x40 0x04 → LEA eax,[rax+4]
    auto result = Disasm(std::array<uint8_t, 3>{0x8D, 0x40, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LEA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(DisasmTest, REX_B_LEA_0x8D_mem_form_stays_abstract)
{
    auto no_prefix = Disasm(std::array<uint8_t, 2>{0x8D, 0x00});
    EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::LEA);
    EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(no_prefix.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(no_prefix.length, 2);

    auto rex_b = Disasm(std::array<uint8_t, 3>{0x41, 0x8D, 0x00});
    EXPECT_EQ(rex_b.instrId.opcode, OpcodeId::LEA);
    EXPECT_EQ(rex_b.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(rex_b.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(rex_b.length, 3);
}

TEST(DisasmTest, LEA_0x8D_Gv_M_SIB_base5_disp32)
{
    // 0x8D 0x04 0x85 + disp32 -> LEA eax, [rax*4 + disp32]
    auto result = Disasm(std::array<uint8_t, 7>{0x8D, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LEA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 7);
}

TEST(DisasmTest, MOVSXD_0x63_Gv_Ev_reg_form)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x63, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSXD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// NOP, XCHG with RAX (0x90-0x97)
// =============================================================================

TEST(DisasmTest, NOP_0x90)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, XCHG_0x91_to_0x97)
{
    for (uint8_t opc = 0x91; opc <= 0x97; ++opc) {
        auto result = Disasm(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::XCHG) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::rax);
    }
}

// =============================================================================
// CWDE, CDQ (0x98-0x99)
// =============================================================================

TEST(DisasmTest, CWDE_0x98)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x98});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CWDE);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CDQ_0x99)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x99});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CDQ);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// MOV moffs (0xA0-0xA3), String ops (0xA4-0xAF)
// =============================================================================

TEST(DisasmTest, MOV_0xA0_al_moffs8)
{
    // 0xA0 + 8-byte absolute address
    std::array<uint8_t, 9> buf = {0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto result = Disasm(buf);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs8);
    EXPECT_EQ(result.length, 9);
}

TEST(DisasmTest, MOV_0xA1_eax_moffs32)
{
    std::array<uint8_t, 9> buf = {0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto result = Disasm(buf);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs32);
    EXPECT_EQ(result.length, 9);
}

TEST(DisasmTest, MOV_0xA2_moffs8_al)
{
    std::array<uint8_t, 9> buf = {0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto result = Disasm(buf);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::moffs8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::al);
    EXPECT_EQ(result.length, 9);
}

TEST(DisasmTest, MOV_0xA3_moffs32_eax)
{
    std::array<uint8_t, 9> buf = {0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto result = Disasm(buf);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::moffs32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::eax);
    EXPECT_EQ(result.length, 9);
}

TEST(DisasmTest, MOVSB_0xA4)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xA4});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSB);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, MOVSD_0xA5)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xA5});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CMPSB_0xA6)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xA6});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPSB);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, STOSB_0xAA)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xAA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STOSB);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, STOSD_0xAB)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xAB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STOSD);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, LODSB_0xAC)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xAC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LODSB);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, SCASB_0xAE)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xAE});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SCASB);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, SCASD_0xAF)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xAF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SCASD);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// TEST al/eax with immediate (0xA8-0xA9)
// =============================================================================

TEST(DisasmTest, TEST_0xA8_al_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xA8, 0xFF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, TEST_0xA9_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xA9, 0xFF, 0xFF, 0xFF, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TEST);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

// =============================================================================
// MOV reg, imm (0xB0-0xBF)
// =============================================================================

TEST(DisasmTest, MOV_0xB0_al_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xB0, 0x42});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, MOV_0xB8_eax_imm32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xB8, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, REX_W_MOV_0xB8_rax_imm64)
{
    // REX.W (0x48) + 0xB8 + 8-byte immediate → abstract MOV r64, imm64
    // length = 1 (REX) + 1 (opcode) + 8 (imm64) = 10
    auto result = Disasm(std::array<uint8_t, 10>{0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm64);
    EXPECT_EQ(result.length, 10);
}

TEST(DisasmTest, REX_W_MOV_0xBB_rbx_imm64)
{
    // REX.W (0x48) + 0xBB + 8-byte immediate → abstract MOV r64, imm64
    // length = 1 (REX) + 1 (opcode) + 8 (imm64) = 10
    auto result = Disasm(std::array<uint8_t, 10>{0x48, 0xBB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm64);
    EXPECT_EQ(result.length, 10);
}

TEST(DisasmTest, Prefix66_MOV_0xB8_ax_imm16)
{
    // 0x66 + 0xB8 + 2-byte immediate → abstract MOV r16, imm16
    // length = 1 (0x66) + 1 (opcode) + 2 (imm16) = 4
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xB8, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, Prefix66_MOV_0xBD_bp_imm16)
{
    // 0x66 + 0xBD + 2-byte immediate → abstract MOV r16, imm16
    // length = 1 (0x66) + 1 (opcode) + 2 (imm16) = 4
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xBD, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, REX_B_MOV_0xB8_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 6>{0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
    EXPECT_EQ(result.length, 6);
}

TEST(DisasmTest, REX_WB_MOV_0xBB_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 10>{0x49, 0xBB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm64);
    EXPECT_EQ(result.length, 10);
}

TEST(DisasmTest, MOV_0xB8_prefix_matrix_width_and_length)
{
    {
        auto result = Disasm(std::array<uint8_t, 5>{0xB8, 0x01, 0x00, 0x00, 0x00});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
        EXPECT_EQ(result.length, 5);
    }
    {
        auto result = Disasm(std::array<uint8_t, 10>{0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm64);
        EXPECT_EQ(result.length, 10);
    }
    {
        auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xB8, 0x01, 0x00});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
        EXPECT_EQ(result.length, 4);
    }
    {
        auto result = Disasm(std::array<uint8_t, 6>{0x41, 0xB8, 0x01, 0x00, 0x00, 0x00});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm32);
        EXPECT_EQ(result.length, 6);
    }
}

TEST(DisasmTest, REX_B_ADD_0x00_modrm_reg_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x41, 0x00, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// RET (0xC2, 0xC3), ENTER/LEAVE (0xC8/0xC9), RETF (0xCA/0xCB)
// =============================================================================

TEST(DisasmTest, RET_near_with_imm16)
{
    auto result = Disasm(std::array<uint8_t, 3>{0xC2, 0x10, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.length, 3);
}

TEST(DisasmTest, RET_near)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, Prefix66_RET_near_with_imm16_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xC2, 0x10, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, REX_W_RET_near_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x48, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, Prefix66_REX_W_RET_near_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x48, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 3);
}

TEST(DisasmTest, ENTER_0xC8)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xC8, 0x10, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ENTER);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, ENTER_0xC8_edge_immediates)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xC8, 0xFF, 0xFF, 0xFF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ENTER);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, Prefix66_ENTER_0xC8_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0xC8, 0x10, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ENTER);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, LEAVE_0xC9)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xC9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LEAVE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, REX_W_LEAVE_0xC9_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x48, 0xC9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LEAVE);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, RETF_0xCA_imm16)
{
    auto result = Disasm(std::array<uint8_t, 3>{0xCA, 0x10, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RETF);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.length, 3);
}

TEST(DisasmTest, RETF_0xCB)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xCB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RETF);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, Prefix66_RETF_0xCA_imm16_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0xCA, 0x10, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RETF);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

TEST(DisasmTest, REX_W_RETF_0xCB_length_consistent)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x48, 0xCB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RETF);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// INT, INT3, IRETD (0xCC-0xCF)
// =============================================================================

TEST(DisasmTest, INT3_0xCC)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xCC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INT3);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, INT_0xCD_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xCD, 0x80});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, IRETD_0xCF)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xCF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IRETD);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// XLAT (0xD7)
// =============================================================================

TEST(DisasmTest, XLAT_0xD7)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xD7});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XLAT);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// LOOP, LOOPE, LOOPNE, JRCXZ (0xE0-0xE3)
// =============================================================================

TEST(DisasmTest, LOOPNE_0xE0)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE0, 0xFE});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LOOPNE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, LOOPE_0xE1)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE1, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LOOPE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, LOOP_0xE2)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE2, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LOOP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, JRCXZ_0xE3)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE3, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JRCXZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// IN, OUT (0xE4-0xE7, 0xEC-0xEF)
// =============================================================================

TEST(DisasmTest, IN_0xE4_al_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE4, 0x60});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IN);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, IN_0xE5_eax_imm8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE5, 0x60});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IN);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, OUT_0xE6_imm8_al)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xE6, 0x60});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OUT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::al);
    EXPECT_EQ(result.length, 2);
}

TEST(DisasmTest, IN_0xEC_al_dx)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xEC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IN);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::dx);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, OUT_0xEE_dx_al)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xEE});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::OUT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::dx);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::al);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// CALL, JMP (0xE8-0xEB)
// =============================================================================

TEST(DisasmTest, CALL_0xE8_rel32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xE8, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, JMP_0xE9_rel32)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xE9, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel32);
    EXPECT_EQ(result.length, 5);
}

TEST(DisasmTest, JMP_0xEB_rel8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0xEB, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// Flags & System: HLT, CMC, CLC, STC, CLI, STI, CLD, STD
// =============================================================================

TEST(DisasmTest, HLT_0xF4)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF4});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::HLT);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CMC_0xF5)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF5});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMC);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CLC_0xF8)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLC);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, STC_0xF9)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xF9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STC);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CLI_0xFA)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLI);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, STI_0xFB)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STI);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, CLD_0xFC)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLD);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, STD_0xFD)
{
    auto result = Disasm(std::array<uint8_t, 1>{0xFD});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STD);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// PUSHFQ, POPFQ (0x9C, 0x9D)
// =============================================================================

TEST(DisasmTest, PUSHFQ_0x9C)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x9C});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSHFQ);
    EXPECT_EQ(result.length, 1);
}

TEST(DisasmTest, POPFQ_0x9D)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x9D});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POPFQ);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// ModRM disp8 / disp32 encoding tests
// =============================================================================

TEST(DisasmTest, ADD_0x00_modrm_mod01_disp8)
{
    // mod=01 r/m=000 => [rax+disp8]: 2 (opcode+modrm) + 1 disp8 = 3
    auto result = Disasm(std::array<uint8_t, 3>{0x00, 0x40, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 3);
}

TEST(DisasmTest, ADD_0x01_modrm_mod10_disp32)
{
    // mod=10 r/m=000 => [rax+disp32]: 2 + 4 = 6
    auto result = Disasm(std::array<uint8_t, 6>{0x01, 0x80, 0x00, 0x10, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 6);
}

// =============================================================================
// Invalid / error cases
// =============================================================================

TEST(DisasmTest, EmptyBuffer_returnsInvalid)
{
    gsl::span<uint8_t> empty{};
    auto result = X64Traits::Disasm(empty);
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(DisasmTest, InvalidOpcode_0x06_returnsInvalid)
{
    // 0x06 is invalid in 64-bit mode
    auto result = Disasm(std::array<uint8_t, 1>{0x06});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(DisasmTest, REX_prefix_followed_by_invalid)
{
    // REX alone then 0xD6 (invalid) - should fail
    auto result = Disasm(std::array<uint8_t, 2>{0x48, 0xD6});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
}
