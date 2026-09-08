// test_x86_x87_opcodes.cpp
// Unit tests for the x87 (D8-DF) opcode family dispatched via case 0x87 in
// xendiza_x86.cpp. These exercise the previously-untested (in 32-bit mode)
// GetInstructionDescriptor_x87 shared helper, covering both memory forms
// (mod != 11) and register forms (mod == 11), plus the SIB-base-5 disp32
// length correction and reserved/invalid ModR/M encodings.
//
// All tests use the public xendiza::Disasm<32> entry point. 32-bit mode has
// no REX prefix; FWAIT (0x9B) precedes many x87 opcodes in real code, but the
// decoder treats 0x9B as its own single-byte FWAIT mnemonic (dispatch 0x01),
// so the D8-DF opcodes here are decoded standalone.

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
// D8 memory forms: FADD/FMUL/FCOM/FCOMP/FSUB/FSUBR/FDIV/FDIVR st0, m32fp
// =============================================================================

TEST(X86x87Test, D8_mem_FADD_st0_m32fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0x00}); // /0 FADD st0, [eax]
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D8_mem_FCOM_m32fp_single_operand)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0x10}); // /2 FCOM [eax]
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCOM);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32fp);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D8_mem_FDIVR_st0_m32fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0x38}); // /7 FDIVR st0, [eax]
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FDIVR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32fp);
    EXPECT_EQ(result.length, 2);
}

// D8 register forms: FADD/FMUL/FSUB/FSUBR/FDIV/FDIVR st0, sti; FCOM/FCOMP sti
TEST(X86x87Test, D8_reg_FADD_st0_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0xC0}); // /0 FADD st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D8_reg_FCOMP_sti_single_operand)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0xD8}); // /3 FCOMP st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCOMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// D9 memory forms: FLD m32fp / FST m32fp / FSTP m32fp / FLDENV m / FLDCW m16 /
//                  FNSTENV m / FNSTCW m16  (/1 is reserved -> UNDEFINED)
// =============================================================================

TEST(X86x87Test, D9_mem_FLD_m32fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0x00}); // /0 FLD m32fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_mem_FLDCW_m16)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0x28}); // /5 FLDCW m16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLDCW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_mem_FNSTENV_m)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0x30}); // /6 FNSTENV m
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNSTENV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_mem_reserved_slash1_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0x08}); // /1 reserved
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// D9 register forms: FLD/FXCH sti, then fixed-ModR/M specials
TEST(X86x87Test, D9_reg_FLD_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xC0}); // /0 FLD st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_reg_FXCH_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xC8}); // /1 FXCH st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FXCH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_reg_FNOP_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xD0}); // FNOP
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNOP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_reg_FLD1_constant)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xE8}); // FLD1
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD1);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_reg_FSQRT_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xFA}); // FSQRT
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FSQRT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, D9_reg_FCHS_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD9, 0xE0}); // FCHS
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCHS);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// DA memory forms: FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR m32
// =============================================================================

TEST(X86x87Test, DA_mem_FIADD_m32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDA, 0x00}); // /0 FIADD m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FIADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DA_mem_FIDIVR_m32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDA, 0x38}); // /7 FIDIVR m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FIDIVR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

// DA register forms: FCMOVcc st0,sti (reg 0-3); FUCOMPP (modrm 0xE9)
TEST(X86x87Test, DA_reg_FCMOVcc_st0_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDA, 0xC0}); // /0 FCMOVcc st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCMOVcc);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DA_reg_FUCOMPP_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDA, 0xE9}); // FUCOMPP
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FUCOMPP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// DB memory forms: FILD m32 / FIST m32 / FISTP m32 / FLD m80fp / FSTP m80fp
//                  (/1,/4,/6 reserved)
// =============================================================================

TEST(X86x87Test, DB_mem_FILD_m32)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0x00}); // /0 FILD m32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FILD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DB_mem_FLD_m80fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0x28}); // /5 FLD m80fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DB_mem_reserved_slash1_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0x08}); // /1 reserved
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// DB register forms: FNCLEX/FNINIT (modrm 0xE2/0xE3); FUCOMI/FCOMI st0,sti
TEST(X86x87Test, DB_reg_FNCLEX_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0xE2}); // FNCLEX
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNCLEX);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DB_reg_FNINIT_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0xE3}); // FNINIT
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNINIT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DB_reg_FCOMI_st0_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDB, 0xF0}); // /6 FCOMI st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCOMI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// DC memory forms: FADD/FMUL/FCOM/FCOMP/FSUB/FSUBR/FDIV/FDIVR st0, m64fp
// =============================================================================

TEST(X86x87Test, DC_mem_FMUL_st0_m64fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDC, 0x08}); // /1 FMUL st0, m64fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64fp);
    EXPECT_EQ(result.length, 2);
}

// DC register forms: operands reversed (sti, st0); SUB/DIV swap to SUBR/DIVR
TEST(X86x87Test, DC_reg_FADD_sti_st0_reversed)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDC, 0xC0}); // /0 FADD st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::st0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DC_reg_FSUBR_sti_st0_swap)
{
    // DC /4 is FSUBR sti, st0 (note: reversed vs D8 where /4 is FSUB st0, sti)
    auto result = Disasm32(std::array<uint8_t, 2>{0xDC, 0xE0}); // /4 FSUBR st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FSUBR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::st0);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// DD memory forms: FLD m64fp / FST m64fp / FSTP m64fp / FRSTOR m /
//                  FSAVE m / FNSTSW m16  (/1,/5 reserved)
// =============================================================================

TEST(X86x87Test, DD_mem_FLD_m64fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDD, 0x00}); // /0 FLD m64fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DD_mem_FRSTOR_m)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDD, 0x20}); // /4 FRSTOR m
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FRSTOR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DD_mem_FNSTSW_m16)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDD, 0x38}); // /7 FNSTSW m16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNSTSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 2);
}

// DD register forms: FFREE/FST/FSTP/FUCOM/FUCOMP sti
TEST(X86x87Test, DD_reg_FFREE_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDD, 0xC0}); // /0 FFREE st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FFREE);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DD_reg_FUCOMP_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDD, 0xE8}); // /5 FUCOMP st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FUCOMP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// DE memory forms: FIADD/FIMUL/FICOM/FICOMP/FISUB/FISUBR/FIDIV/FIDIVR m16
// =============================================================================

TEST(X86x87Test, DE_mem_FIADD_m16)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDE, 0x00}); // /0 FIADD m16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FIADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 2);
}

// DE register forms: FCOMPP (modrm 0xD9); FADDP/FMULP/FSUBRP/FSUBP/FDIVRP/FDIVP
TEST(X86x87Test, DE_reg_FCOMPP_fixed_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDE, 0xD9}); // FCOMPP
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCOMPP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DE_reg_FADDP_sti_st0)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDE, 0xC0}); // /0 FADDP st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADDP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::sti);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::st0);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DE_reg_invalid_slash2_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDE, 0xD0}); // /2 invalid
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// DF memory forms: FILD m16 / FISTTP m16 / FIST m16 / FISTP m16 /
//                  FBLD m80fp / FILD m64 / FBSTP m80fp / FISTP m64
// =============================================================================

TEST(X86x87Test, DF_mem_FILD_m16)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0x00}); // /0 FILD m16
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FILD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DF_mem_FBLD_m80fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0x20}); // /4 FBLD m80fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FBLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DF_mem_FILD_m64)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0x28}); // /5 FILD m64
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FILD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DF_mem_FBSTP_m80fp)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0x30}); // /6 FBSTP m80fp
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FBSTP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m80fp);
    EXPECT_EQ(result.length, 2);
}

// DF register forms: FNSTSW ax (modrm 0xE0); FUCOMIP/FCOMIP st0,sti
TEST(X86x87Test, DF_reg_FNSTSW_ax)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0xE0}); // FNSTSW ax
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FNSTSW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.length, 2);
}

TEST(X86x87Test, DF_reg_FCOMIP_st0_sti)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xDF, 0xF0}); // /6 FCOMIP st0, st0
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FCOMIP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::sti);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// FWAIT (0x9B) standalone mnemonic
// =============================================================================

TEST(X86x87Test, FWAIT_0x9B_standalone)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x9B});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FWAIT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// SIB base=5 disp32 length correction for x87 memory forms (case 0x87)
// =============================================================================

TEST(X86x87Test, D8_mem_SIB_base5_disp32_length)
{
    // D8 04 85 78 56 34 12 -> FADD st0, m32fp [eax*4 + disp32]
    auto result = Disasm32(std::array<uint8_t, 7>{0xD8, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32fp);
    EXPECT_EQ(result.length, 7); // opcode + modrm + sib + disp32
}

TEST(X86x87Test, D9_mem_FLDCW_SIB_base5_disp32_length)
{
    // D9 2C 85 78 56 34 12 -> FLDCW m16 [eax*4 + disp32]
    auto result = Disasm32(std::array<uint8_t, 7>{0xD9, 0x2C, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FLDCW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m16);
    EXPECT_EQ(result.length, 7);
}

// =============================================================================
// Buffer-too-short error paths
// =============================================================================

TEST(X86x87Test, BufferTooShort_missing_modrm)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86x87Test, BufferTooShort_SIB_disp32)
{
    // case 0x87 adds +4 to the length when SIB.base==5 (mandatory disp32) and
    // verifies those 4 disp32 bytes are present before reporting success.
    // {D8 04 85} ends right after the SIB byte, so the decode must report
    // INSUFFICIENT_BUFFER rather than a length-7 success.
    auto result = Disasm32(std::array<uint8_t, 3>{0xD8, 0x04, 0x85});
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86x87Test, BufferTooShort_SIB_missing_sib_byte)
{
    // modrm=0x04 (SIB) but buffer ends right after modrm
    auto result = Disasm32(std::array<uint8_t, 2>{0xD8, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}
