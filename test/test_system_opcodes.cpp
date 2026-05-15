// test_system_opcodes.cpp
// Tests for 0F 00, 0F 01, 0F 18, 0F 20-23, and 0F C7 system/privileged instruction decode paths.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include "../xendiza_x64.hpp"

using namespace xendiza;
using namespace xendiza::detail;

template <size_t N>
static DecodedInstruction Disasm(const std::array<uint8_t, N>& buf)
{
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), N));
}

// ---------------------------------------------------------------------------
// 0F 00 group — Group 6 descriptor-table register instructions
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, SLDT_0F00_slash0_mem)
{
    // 0F 00 00  ->  SLDT [rax]  (mod=00, reg=0, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SLDT);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SLDT_0F00_slash0_reg)
{
    // 0F 00 C0  ->  SLDT eax  (mod=11, reg=0, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SLDT);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SLDT_0F00_slash0_REXW_reg)
{
    // 48 0F 00 C0  ->  SLDT rax  (REX.W upgrades r32→r64)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x00, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SLDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, STR_0F00_slash1_mem)
{
    // 0F 00 08  ->  STR [rax]  (mod=00, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::STR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, STR_0F00_slash1_reg)
{
    // 0F 00 C8  ->  STR eax  (mod=11, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xC8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::STR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LLDT_0F00_slash2_mem)
{
    // 0F 00 10  ->  LLDT [rax]  (mod=00, reg=2, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LLDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LLDT_0F00_slash2_reg)
{
    // 0F 00 D0  ->  LLDT ax  (mod=11, reg=2, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xD0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LLDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LTR_0F00_slash3_mem)
{
    // 0F 00 18  ->  LTR [rax]  (mod=00, reg=3, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x18});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LTR_0F00_slash3_reg)
{
    // 0F 00 D8  ->  LTR ax  (mod=11, reg=3, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xD8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, VERR_0F00_slash4_mem)
{
    // 0F 00 20  ->  VERR [rax]  (mod=00, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x20});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::VERR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, VERR_0F00_slash4_reg)
{
    // 0F 00 E0  ->  VERR ax  (mod=11, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xE0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::VERR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, VERW_0F00_slash5_mem)
{
    // 0F 00 28  ->  VERW [rax]  (mod=00, reg=5, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x28});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::VERW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, VERW_0F00_slash5_reg)
{
    // 0F 00 E8  ->  VERW ax  (mod=11, reg=5, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0xE8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::VERW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, OpcodeExt_0F00_invalid_slash6)
{
    // 0F 00 30  ->  /6 (mod=00, reg=6) — undefined
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0F00_invalid_slash7)
{
    // 0F 00 38  ->  /7 (mod=00, reg=7) — undefined
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x00, 0x38});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0F00_insufficient_buffer)
{
    // 0F 00  ->  only 2 bytes, ModRM missing
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// ---------------------------------------------------------------------------
// 0F 01 group — Group 7: descriptor-table load/store + special register forms
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, SGDT_0F01_slash0_mem)
{
    // 0F 01 00  ->  SGDT [rax]  (mod=00, reg=0, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SGDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SIDT_0F01_slash1_mem)
{
    // 0F 01 08  ->  SIDT [rax]  (mod=00, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SIDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LGDT_0F01_slash2_mem)
{
    // 0F 01 10  ->  LGDT [rax]  (mod=00, reg=2, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LGDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LIDT_0F01_slash3_mem)
{
    // 0F 01 18  ->  LIDT [rax]  (mod=00, reg=3, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x18});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LIDT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SMSW_0F01_slash4_mem)
{
    // 0F 01 20  ->  SMSW [rax]  (mod=00, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x20});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SMSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SMSW_0F01_slash4_reg)
{
    // 0F 01 E0  ->  SMSW eax  (mod=11, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xE0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SMSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SMSW_0F01_slash4_REXW_reg)
{
    // 48 0F 01 E0  ->  SMSW rax  (REX.W, mod=11, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x01, 0xE0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SMSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, LMSW_0F01_slash6_mem)
{
    // 0F 01 30  ->  LMSW [rax]  (mod=00, reg=6, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x30});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LMSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, LMSW_0F01_slash6_reg)
{
    // 0F 01 F0  ->  LMSW ax  (mod=11, reg=6, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::LMSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, INVLPG_0F01_slash7_mem)
{
    // 0F 01 38  ->  INVLPG [rax]  (mod=00, reg=7, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x38});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::INVLPG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, INVLPG_0F01_slash7_mem_disp8)
{
    // 0F 01 78 10  ->  INVLPG [rax + 0x10]  (mod=01, reg=7, rm=0)
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0x01, 0x78, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::INVLPG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, SWAPGS_0F01_F8)
{
    // 0F 01 F8  ->  SWAPGS
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xF8});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::SWAPGS);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, RDTSCP_0F01_F9)
{
    // 0F 01 F9  ->  RDTSCP
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xF9});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::RDTSCP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MONITOR_0F01_C8)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xC8});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::MONITOR);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MWAIT_0F01_C9)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xC9});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::MWAIT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, CLAC_0F01_CA)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xCA});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::CLAC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, STAC_0F01_CB)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xCB});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::STAC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XGETBV_0F01_D0)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xD0});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::XGETBV);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XSETBV_0F01_D1)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xD1});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::XSETBV);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XTEST_0F01_D6)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xD6});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::XTEST);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, RDPKRU_0F01_EE)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xEE});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::RDPKRU);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, WRPKRU_0F01_EF)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xEF});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::WRPKRU);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, SERIALIZE_0F01_E8)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xE8});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::SERIALIZE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, OpcodeExt_0F01_invalid_reg_form)
{
    // 0F 01 C1  ->  mod=11, reg=0, rm=1  — undefined register form for /0
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0F01_invalid_memory_slash5)
{
    // 0F 01 28  ->  mod=00, reg=5, rm=0  — /5 memory form is undefined
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x01, 0x28});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0F01_insufficient_buffer)
{
    // 0F 01  ->  only 2 bytes, ModRM missing
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// ---------------------------------------------------------------------------
// 0F 18 group - Group 16: PREFETCHNTA/T0/T1/T2 + reserved NOP forms
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, PREFETCHNTA_0F18_slash0_mem)
{
    // 0F 18 00  ->  PREFETCHNTA [rax]  (mod=00, reg=0, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x18, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, PREFETCHT0_0F18_slash1_mem_disp8)
{
    // 0F 18 48 10  ->  PREFETCHT0 [rax + 0x10]  (mod=01, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0x18, 0x48, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHT0);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, PREFETCHT1_0F18_slash2_mem)
{
    // 0F 18 10  ->  PREFETCHT1 [rax]  (mod=00, reg=2, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x18, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHT1);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, PREFETCHT2_0F18_slash3_mem)
{
    // 0F 18 18  ->  PREFETCHT2 [rax]  (mod=00, reg=3, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x18, 0x18});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHT2);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_slash4_mem_is_nop)
{
    // 0F 18 20  ->  reserved memory form /4; decoded as NOP
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x18, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_register_form_is_nop)
{
    // 0F 18 C0  ->  reserved register form; decoded as NOP
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x18, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_Prefix66_length_only)
{
    // 66 0F 18 00  ->  PREFETCHNTA [rax] (prefix does not alter operands)
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x18, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_REXW_length_only)
{
    // 48 0F 18 00  ->  PREFETCHNTA [rax] (REX.W should only affect length)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x18, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_SIB_disp32_boundary_length)
{
    // 0F 18 04 25 FF FF FF 7F  ->  PREFETCHNTA [disp32] (SIB + disp32 boundary)
    // modrm=04 enables SIB; sib=25 (scale=0,index=none,base=5) forces disp32.
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0x18, 0x04, 0x25, 0xFF, 0xFF, 0xFF, 0x7F});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::PREFETCHNTA);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 8);
}

TEST(SystemOpcodeTest, OpcodeExt_0F18_insufficient_buffer)
{
    // 0F 18  ->  only 2 bytes, ModRM missing
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x18});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// ---------------------------------------------------------------------------
// 0F 1C group - CLDEMOTE /0 memory form
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, CLDEMOTE_0F1C_slash0_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1C, 0x00});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CLDEMOTE);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, CLDEMOTE_0F1C_slash0_mem_disp8)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0x1C, 0x40, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CLDEMOTE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0F1C_invalid_register_form)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1C, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0F1C_invalid_memory_slash1)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1C, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, ENDBR64_F30F1E_FA)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x1E, 0xFA});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::ENDBR64);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, ENDBR32_F30F1E_FB)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x1E, 0xFB});
    EXPECT_EQ(result.instrId.opcode,        OpcodeId::ENDBR32);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, ENDBR_0F1E_without_F3_invalid)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1E, 0xFA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, ENDBR_0F1E_insufficient_buffer)
{
    auto result = Disasm(std::array<uint8_t, 3>{0xF3, 0x0F, 0x1E});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// ---------------------------------------------------------------------------
// 0F 20-23 — MOV to/from control registers and debug registers
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, MOV_0F20_Rd_CRn)
{
    // 0F 20 C0  ->  MOV rax, cr0  (mod=11, reg=0(cr0), rm=0(rax))
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x20, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count,       2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::creg);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MOV_0F21_Rd_DRn)
{
    // 0F 21 C0  ->  MOV rax, dr0  (mod=11, reg=0(dr0), rm=0(rax))
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x21, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operand_count,       2);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::dr);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MOV_0F22_CRn_Rd)
{
    // 0F 22 C0  ->  MOV cr0, rax
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x22, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::creg);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MOV_0F23_DRn_Rd)
{
    // 0F 23 C0  ->  MOV dr0, rax
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x23, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::dr);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MOV_0F20_REXW_length)
{
    // 48 0F 20 C0  ->  MOV rax, cr0  (REX.W prefix; length = 4)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x20, 0xC0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::creg);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, MOV_0F22_with_different_regs)
{
    // 0F 22 D8  ->  MOV cr3, rax  (mod=11, reg=3(cr3), rm=0(rax))
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x22, 0xD8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::creg);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, MOV_0F20_memory_form_invalid)
{
    // 0F 20 00  ->  mod=00 memory form; undefined for this register-only opcode
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x20, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, MOV_0F21_memory_form_invalid)
{
    // 0F 21 00  ->  mod=00 memory form; undefined for this register-only opcode
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x21, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, MOV_0F22_memory_form_invalid)
{
    // 0F 22 00  ->  mod=00 memory form; undefined for this register-only opcode
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x22, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, MOV_0F23_memory_form_invalid)
{
    // 0F 23 00  ->  mod=00 memory form; undefined for this register-only opcode
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x23, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, MOV_0F20_insufficient_buffer)
{
    // 0F 20  ->  only 2 bytes, ModRM missing
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// ---------------------------------------------------------------------------
// 0F C7 Group 9: CMPXCHG8B, CMPXCHG16B, RDRAND, RDSEED
// ---------------------------------------------------------------------------

TEST(SystemOpcodeTest, CMPXCHG8B_0FC7_slash1_mem)
{
    // 0F C7 08  ->  CMPXCHG8B [rax]  (mod=00, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CMPXCHG8B);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, CMPXCHG8B_0FC7_slash1_mem_disp8)
{
    // 0F C7 48 10  ->  CMPXCHG8B [rax + 0x10]  (mod=01, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xC7, 0x48, 0x10});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CMPXCHG8B);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, CMPXCHG16B_0FC7_REXW_slash1_mem)
{
    // 48 0F C7 08  ->  CMPXCHG16B [rax]  (REX.W, mod=00, reg=1, rm=0)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xC7, 0x08});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::CMPXCHG16B);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_slash1_reg_invalid)
{
    // 0F C7 C8  ->  mod=11, reg=1 (CMPXCHG8B has no register form)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, XRSTORS_0FC7_slash3_mem)
{
    // 0F C7 18  ->  XRSTORS [rax]  (mod=00, reg=3, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x18});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XRSTORS);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XRSTORS_0FC7_slash3_mem_sib_disp32)
{
    // 0F C7 1C 25 78 56 34 12  ->  XRSTORS [disp32] (SIB + disp32)
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0xC7, 0x1C, 0x25, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XRSTORS);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 8);
}

TEST(SystemOpcodeTest, XSAVEC_0FC7_slash4_mem)
{
    // 0F C7 20  ->  XSAVEC [rax]  (mod=00, reg=4, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x20});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XSAVEC);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XSAVEC_0FC7_slash4_mem_sib_disp32)
{
    // 0F C7 24 25 78 56 34 12  ->  XSAVEC [disp32] (SIB + disp32)
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0xC7, 0x24, 0x25, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XSAVEC);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 8);
}

TEST(SystemOpcodeTest, XSAVES_0FC7_slash5_mem)
{
    // 0F C7 28  ->  XSAVES [rax]  (mod=00, reg=5, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x28});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XSAVES);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, XSAVES_0FC7_slash5_mem_sib_disp32)
{
    // 0F C7 2C 25 78 56 34 12  ->  XSAVES [disp32] (SIB + disp32)
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0xC7, 0x2C, 0x25, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::XSAVES);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 8);
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_slash4_reg_invalid)
{
    // 0F C7 E0  ->  mod=11, reg=4 (XSAVEC has no register form)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, RDRAND_0FC7_slash6_reg)
{
    // 0F C7 F0  ->  RDRAND eax  (mod=11, reg=6, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDRAND);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, RDRAND_0FC7_slash6_REXW_reg)
{
    // 48 0F C7 F0  ->  RDRAND rax  (REX.W)
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xC7, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDRAND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, RDRAND_0FC7_slash6_Prefix66_reg)
{
    // 66 0F C7 F0  ->  RDRAND ax  (66h prefix)
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xC7, 0xF0});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDRAND);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_slash6_mem_invalid)
{
    // 0F C7 30  ->  mod=00, reg=6 (memory form not handled here)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, RDSEED_0FC7_slash7_reg)
{
    // 0F C7 F8  ->  RDSEED eax  (mod=11, reg=7, rm=0)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0xF8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDSEED);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(SystemOpcodeTest, RDPID_F30FC7_slash7_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xC7, 0xF8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDPID);
    EXPECT_EQ(result.instrId.operand_count,       1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, RDPID_F3_REXW_0FC7_slash7_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xF3, 0x48, 0x0F, 0xC7, 0xF8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDPID);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 5);
}

TEST(SystemOpcodeTest, RDPID_F3_0FC7_slash7_mem_invalid)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xC7, 0x38});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, RDSEED_0FC7_slash7_REXW_reg)
{
    // 48 0F C7 F8  ->  RDSEED rax
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xC7, 0xF8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDSEED);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, RDSEED_0FC7_slash7_Prefix66_reg)
{
    // 66 0F C7 F8  ->  RDSEED ax
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xC7, 0xF8});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::RDSEED);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_slash7_mem_invalid)
{
    // 0F C7 38  ->  mod=00, reg=7 (memory form not handled here)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x38});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_invalid_slash0)
{
    // 0F C7 00  ->  mod=00, reg=0 — undefined
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC7, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(SystemOpcodeTest, OpcodeExt_0FC7_insufficient_buffer)
{
    // 0F C7  ->  only 2 bytes, ModRM missing
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xC7});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

