#ifndef XENDIZA_HPP
#define XENDIZA_HPP

#include <cstddef>

#include "xendiza_x86.hpp"
#include "xendiza_x64.hpp"

namespace xendiza {

template <size_t Bits>
inline auto Disasm(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction = delete;

template <>
inline auto Disasm<32>(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
	return detail::X86Traits::Disasm(buffer);
}

template <>
inline auto Disasm<64>(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
	return detail::X64Traits::Disasm(buffer);
}

template <size_t Bits>
inline auto Disasm(gsl::span<const std::byte> buffer) noexcept -> DecodedInstruction = delete;

template <>
inline auto Disasm<32>(gsl::span<const std::byte> buffer) noexcept -> DecodedInstruction
{
	auto* data = reinterpret_cast<const uint8_t*>(buffer.data());
	return detail::X86Traits::Disasm(gsl::span<const uint8_t>(data, buffer.size()));
}

template <>
inline auto Disasm<64>(gsl::span<const std::byte> buffer) noexcept -> DecodedInstruction
{
	auto* data = reinterpret_cast<const uint8_t*>(buffer.data());
	return detail::X64Traits::Disasm(gsl::span<const uint8_t>(data, buffer.size()));
}

} // namespace xendiza

#endif // XENDIZA_HPP
