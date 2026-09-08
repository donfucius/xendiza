#include <xendiza/xendiza_c.h>
#include <xendiza/xendiza.hpp>

namespace {

auto MakeErrorResult(const xendiza::ErrorCode errcode) noexcept -> xendiza_decoded_instruction_t
{
	xendiza_decoded_instruction_t result{};
	result.length = static_cast<uint8_t>(errcode);
	result.opcode = static_cast<uint16_t>(xendiza::OpcodeId::INVALID_OPCODE);
	result.operand_count = 0;
	result.operands[0] = static_cast<uint16_t>(xendiza::Operand::invalid);
	result.operands[1] = static_cast<uint16_t>(xendiza::Operand::invalid);
	result.operands[2] = static_cast<uint16_t>(xendiza::Operand::invalid);
	result.operands[3] = static_cast<uint16_t>(xendiza::Operand::invalid);
	return result;
}

} // namespace

extern "C" auto xendiza_disasm64(const uint8_t* buffer, const size_t size) -> xendiza_decoded_instruction_t
{
	if (buffer == nullptr && size != 0) {
		return MakeErrorResult(xendiza::ErrorCode::INSUFFICIENT_BUFFER);
	}

	const auto span = gsl::span(buffer, size);
	const auto [length, instrId] = xendiza::Disasm<64>(span);

	xendiza_decoded_instruction_t result{};
	result.length = length;
	result.opcode = static_cast<uint16_t>(instrId.opcode);
	result.operand_count = instrId.operand_count;
	result.operands[0] = static_cast<uint16_t>(instrId.operands.operand[0]);
	result.operands[1] = static_cast<uint16_t>(instrId.operands.operand[1]);
	result.operands[2] = static_cast<uint16_t>(instrId.operands.operand[2]);
	result.operands[3] = static_cast<uint16_t>(instrId.operands.operand[3]);
	return result;
}

extern "C" auto xendiza_disasm32(const uint8_t* buffer, const size_t size) -> xendiza_decoded_instruction_t
{
	if (buffer == nullptr && size != 0) {
		return MakeErrorResult(xendiza::ErrorCode::INSUFFICIENT_BUFFER);
	}

	const auto span = gsl::span(buffer, size);
	const auto [length, instrId] = xendiza::Disasm<32>(span);

	xendiza_decoded_instruction_t result{};
	result.length = length;
	result.opcode = static_cast<uint16_t>(instrId.opcode);
	result.operand_count = instrId.operand_count;
	result.operands[0] = static_cast<uint16_t>(instrId.operands.operand[0]);
	result.operands[1] = static_cast<uint16_t>(instrId.operands.operand[1]);
	result.operands[2] = static_cast<uint16_t>(instrId.operands.operand[2]);
	result.operands[3] = static_cast<uint16_t>(instrId.operands.operand[3]);
	return result;
}



