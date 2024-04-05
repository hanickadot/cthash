#ifndef CTHASH_UUID_CONVERSIONS_HPP
#define CTHASH_UUID_CONVERSIONS_HPP

#include <span>
#include <utility>

namespace cthash::utility {

template <std::unsigned_integral T, std::size_t N = sizeof(T)> constexpr T little_endian_bytes_to(std::span<const std::byte, N> input) requires(N != std::dynamic_extent) {
	static_assert(N <= sizeof(T));

	return [=]<std::size_t... Idx>(std::index_sequence<Idx...>) {
		return static_cast<T>(((static_cast<T>(input[Idx]) << (Idx * 8u)) | ...));
	}(std::make_index_sequence<N>());
}

template <std::unsigned_integral T, std::size_t N = sizeof(T)> constexpr T big_endian_bytes_to(std::span<const std::byte, N> input) requires(N != std::dynamic_extent) {
	constexpr std::size_t base = N * 8u - 8u;
	static_assert(N <= sizeof(T));

	return [=]<std::size_t... Idx>(std::index_sequence<Idx...>) {
		return static_cast<T>(((static_cast<T>(input[Idx]) << (base - (Idx * 8u))) | ...));
	}(std::make_index_sequence<N>());
}

} // namespace cthash::utility

#endif
