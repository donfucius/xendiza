// test_x86_2byte_opcodes.cpp
// Unit tests for X86Traits::Decode2ByteOpcode (0F-prefixed opcodes in 32-bit mode).
// All tests use xendiza::Disasm<32>() via the public API.

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

// ---------------------------------------------------------------------------
// MOVZX  0F B6  Gv, Eb  — x86-32: dest is r32 (no r64 form)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVZX_0FB6_modrm_mem_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xB6, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m8);
    EXPECT_EQ(result.instrId.operand_count,       2);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVZX_0FB6_modrm_reg_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVZX_0FB6_66h_modrm_reg_r16)
{
    // 66h prefix shrinks destination to r16 in x86-32.
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, MOVZX_0FB6_SIB_base5_disp32_length)
{
    // 0F B6 04 85 78 56 34 12 → movzx eax, byte ptr [eax*4+0x12345678]
    // modrm=0x04 (mod=00, rm=100 → SIB), sib=0x85 (base=5 → disp32)
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xB6, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m8);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// MOVZX  0F B7  Gv, Ew  — x86-32: dest is r32 (no r64 form)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVZX_0FB7_modrm_mem_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xB7, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m16);
    EXPECT_EQ(result.instrId.operand_count,       2);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVZX_0FB7_SIB_base5_disp32_length)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xB7, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m16);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// MOVSX  0F BE  Gv, Eb  — x86-32: dest is r32 (no r64 form)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVSX_0FBE_modrm_mem_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xBE, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVSX_0FBE_66h_modrm_reg_r16)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0xBE, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// MOVSX  0F BF  Gv, Ew  — x86-32
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVSX_0FBF_modrm_reg_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xBF, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

// ---------------------------------------------------------------------------
// SETcc  0F 90-9F — Eb operand; 66h prefix has no effect on byte size
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, SETO_0F90_modrm_reg)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x90, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SETO);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, SETNZ_0F95_modrm_mem)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x95, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, SETNZ_0F95_66h_operand_stays_byte)
{
    // 66h does not change SETcc operand size — always byte.
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0x95, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, SETcc_0F90_SIB_base5_disp32_length)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0x90, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SETO);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// BSWAP  0F C8-CF — always r32 in x86-32; no REX.W upgrade possible
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, BSWAP_0FC8_always_r32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x0F, 0xC8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86TwoByteOpcodeTest, BSWAP_0FCF_always_r32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x0F, 0xCF});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

// ---------------------------------------------------------------------------
// Multi-byte NOP  0F 1F /0
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, NOP_0F1F_modrm_mem)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x1F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, NOP_0F1F_SIB_base5_disp32_length)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0x1F, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 8);
}

TEST(X86TwoByteOpcodeTest, NOP_0F1F_invalid_slash1)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x1F, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// ---------------------------------------------------------------------------
// SHLD / SHRD  0F A4/AC (Ev, Gv, imm8) and 0F A5/AD (Ev, Gv, CL)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, SHLD_0FA4_imm8_modrm_reg_r32)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x0F, 0xA4, 0xC1, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, SHLD_0FA4_imm8_SIB_base5_disp32_length)
{
    // 0F A4 04 85 78 56 34 12 04  (modrm=0x04 SIB base5, then imm8=0x04)
    auto result = Disasm32(std::array<uint8_t, 9>{0x0F, 0xA4, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 9);
}

TEST(X86TwoByteOpcodeTest, SHLD_0FA5_cl_modrm_reg_r32)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xA5, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::cl);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, SHRD_0FAC_imm8_modrm_mem_r32)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x0F, 0xAC, 0x01, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, SHRD_0FAD_cl_SIB_base5_disp32_length)
{
    // 0F AD 04 85 78 56 34 12  (SHRD mem, r32, CL with SIB base5)
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xAD, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::cl);
    EXPECT_EQ(result.length, 8);
}

TEST(X86TwoByteOpcodeTest, SHLD_66h_0FA4_imm8_modrm_reg_r16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0x0F, 0xA4, 0xC1, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 5);
}

// ---------------------------------------------------------------------------
// 0F AE Group 15 — fences, FXSAVE/FXRSTOR, LDMXCSR, STMXCSR, XSAVE, etc.
// F3 variants (RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE) are undefined in x86-32.
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, LFENCE_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0xE8});
    EXPECT_EQ(result.instrId.opcode,     OpcodeId::LFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MFENCE_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0xF0});
    EXPECT_EQ(result.instrId.opcode,     OpcodeId::MFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, SFENCE_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0xF8});
    EXPECT_EQ(result.instrId.opcode,     OpcodeId::SFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, FXSAVE_0FAE_slash0_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::FXSAVE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, LDMXCSR_0FAE_slash2_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LDMXCSR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, CLFLUSH_0FAE_slash7_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xAE, 0x39});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CLFLUSH);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, RDFSBASE_F30FAE_undefined_in_x86)
{
    // F3 register forms of 0F AE are x64-only.
    auto result = Disasm32(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86TwoByteOpcodeTest, CLFLUSH_0FAE_slash7_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xAE, 0x3C, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CLFLUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// 0F 00 Group 6 — SLDT/STR/LLDT/LTR/VERR/VERW
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, SLDT_0F00_slash0_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x00, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SLDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, LLDT_0F00_slash2_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x00, 0xD0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LLDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

// ---------------------------------------------------------------------------
// 0F 01 Group 7 — SGDT/SIDT/LGDT/LIDT/SMSW/LMSW/INVLPG
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, SGDT_0F01_slash0_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SGDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, INVLPG_0F01_slash7_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x01, 0x38});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::INVLPG);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.length, 3);
}

// ---------------------------------------------------------------------------
// 0F 20-23  MOV creg/dreg — register-only; GPR operand is r32 in x86-32
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOV_CR0_0F20_r32_x86)
{
    // 0F 20 C0 → MOV eax, CR0  (mod=11, reg=000=CR0, rm=000=EAX)
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x20, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);   // destination GPR
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOV_creg_memory_form_invalid_x86)
{
    // Memory form (mod != 11) must return UNDEFINED_INSTRUCTION.
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x20, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// ---------------------------------------------------------------------------
// 0F C7 Group 9 — CMPXCHG8B; no CMPXCHG16B in x86-32 (no REX.W)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, CMPXCHG8B_0FC7_slash1_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xC7, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CMPXCHG8B);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, RDRAND_0FC7_slash6_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xC7, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDRAND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, RDRAND_0FC7_slash6_66h_r16_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0xC7, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDRAND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, CMPXCHG8B_0FC7_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xC7, 0x0C, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CMPXCHG8B);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// 0F 18 Group 16 — PREFETCHNTA/T0/T1/T2 (Group 16)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, PREFETCHNTA_0F18_slash0_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x18, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, PREFETCHT0_0F18_slash1_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x18, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHT0);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, PREFETCHNTA_0F18_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0x18, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// 0F BA Group 8 — BT/BTS/BTR/BTC with imm8
// (dispatch tag 0x63 in x86 — uses DecodeOpcodeExtension_2byte)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, BT_0FBA_slash4_imm8_modrm_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x0F, 0xBA, 0xE0, 0x07});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, BTS_0FBA_slash5_imm8_modrm_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x0F, 0xBA, 0x29, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BTS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, BT_0FBA_slash4_SIB_base5_disp32_length_x86)
{
    // 0F BA 24 85 78 56 34 12 07  (BT [eax*4+disp32], imm8=0x07)
    auto result = Disasm32(std::array<uint8_t, 9>{0x0F, 0xBA, 0x24, 0x85, 0x78, 0x56, 0x34, 0x12, 0x07});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 9);
}

TEST(X86TwoByteOpcodeTest, BT_0FBA_invalid_slash0_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x0F, 0xBA, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// ---------------------------------------------------------------------------
// 0F C3  MOVNTI m32, r32 — always 32-bit form in x86-32 (no REX.W)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVNTI_0FC3_m32_r32_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xC3, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVNTI_0FC3_register_form_invalid_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xC3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86TwoByteOpcodeTest, MOVNTI_0FC3_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0xC3, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 8);
}

// ---------------------------------------------------------------------------
// MOVUPS  0F 10/11  (SIMD, dispatch tag 0x65)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, MOVUPS_0F10_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x10, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, MOVUPS_0F10_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0x10, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 8);
}

TEST(X86TwoByteOpcodeTest, MOVUPS_0F11_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x11, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m128);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, UCOMISS_0F2E_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x2E, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::UCOMISS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, UCOMISD_660F2E_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0x2E, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::UCOMISD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// SIMD arithmetic families (dispatch tag 0x66): ADDPS/PD/SS/SD etc.
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, ADDPS_0F58_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x58, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADDPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, ADDPD_660F58_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADDPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, ADDSS_F30F58_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0xF3, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADDSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, ADDSD_F20F58_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0xF2, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADDSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(X86TwoByteOpcodeTest, ADDPS_0F58_SIB_base5_disp32_length_x86)
{
    auto result = Disasm32(std::array<uint8_t, 8>{0x0F, 0x58, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADDPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 8);
}

TEST(X86TwoByteOpcodeTest, MULPS_0F59_reg_x86)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0x59, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MULPS);
    EXPECT_EQ(result.length, 3);
}

TEST(X86TwoByteOpcodeTest, DIVSD_F20F5E_mem_x86)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0xF2, 0x0F, 0x5E, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::DIVSD);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// 0F D6 — explicitly undefined in x86-32 (same as x64)
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, OpcodeD6_0F_undefined_x86)
{
    // 0F D6 as a legacy-encoded opcode is not valid in 32-bit mode.
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xD6, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length,         static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// ---------------------------------------------------------------------------
// Error cases: buffer too short
// ---------------------------------------------------------------------------

TEST(X86TwoByteOpcodeTest, BufferTooShort_AfterEscape_x86)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x0F});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86TwoByteOpcodeTest, MOVZX_0FB6_BufferTooShort_for_SIB_x86)
{
    // modrm=0x04 signals SIB, but buffer ends right after modrm ← too short.
    auto result = Disasm32(std::array<uint8_t, 3>{0x0F, 0xB6, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

