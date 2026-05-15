#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <gsl/span>

#include "../xendiza_c.h"
#include "../xendiza.hpp"

TEST(PublicApiTest, Disasm64_Uint8Span)
{
    std::array<uint8_t, 2> code { 0x90, 0x90 }; // NOP

    const auto result = xendiza::Disasm<64>(gsl::span<const uint8_t>(code));

    EXPECT_EQ(result.instrId.opcode, xendiza::OpcodeId::NOP);
    EXPECT_EQ(result.length, 1);
}

TEST(PublicApiTest, Disasm64_ByteSpan)
{
    std::array<std::byte, 2> code { std::byte{0x90}, std::byte{0x90} }; // NOP

    const auto result = xendiza::Disasm<64>(gsl::span<const std::byte>(code));

    EXPECT_EQ(result.instrId.opcode, xendiza::OpcodeId::NOP);
    EXPECT_EQ(result.length, 1);
}

TEST(PublicApiTest, CAbi_Disasm64_Parity)
{
    std::array<uint8_t, 2> code { 0x90, 0x90 }; // NOP

    const auto cpp_result = xendiza::Disasm<64>(gsl::span<const uint8_t>(code));
    const auto c_result = xendiza_disasm64(code.data(), code.size());

    EXPECT_EQ(c_result.length, cpp_result.length);
    EXPECT_EQ(c_result.opcode, static_cast<uint16_t>(cpp_result.instrId.opcode));
    EXPECT_EQ(c_result.operand_count, cpp_result.instrId.operand_count);
    EXPECT_EQ(c_result.operands[0], static_cast<uint16_t>(cpp_result.instrId.operands.operand[0]));
}

TEST(PublicApiTest, Disasm32_Uint8Span)
{
    std::array<uint8_t, 2> code { 0x90, 0x90 }; // NOP

    const auto result = xendiza::Disasm<32>(gsl::span<const uint8_t>(code));

    EXPECT_EQ(result.instrId.opcode, xendiza::OpcodeId::NOP);
    EXPECT_EQ(result.length, 1);
}

TEST(PublicApiTest, Disasm32_ByteSpan)
{
    std::array<std::byte, 2> code { std::byte{0x90}, std::byte{0x90} }; // NOP

    const auto result = xendiza::Disasm<32>(gsl::span<const std::byte>(code));

    EXPECT_EQ(result.instrId.opcode, xendiza::OpcodeId::NOP);
    EXPECT_EQ(result.length, 1);
}

TEST(PublicApiTest, CAbi_Disasm32_Parity)
{
    std::array<uint8_t, 2> code { 0x90, 0x90 }; // NOP

    const auto cpp_result = xendiza::Disasm<32>(gsl::span<const uint8_t>(code));
    const auto c_result = xendiza_disasm32(code.data(), code.size());

    EXPECT_EQ(c_result.length, cpp_result.length);
    EXPECT_EQ(c_result.opcode, static_cast<uint16_t>(cpp_result.instrId.opcode));
    EXPECT_EQ(c_result.operand_count, cpp_result.instrId.operand_count);
    EXPECT_EQ(c_result.operands[0], static_cast<uint16_t>(cpp_result.instrId.operands.operand[0]));
}

