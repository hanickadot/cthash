#ifndef CTHASH_INTERNAL_HEXDEC_HPP
#define CTHASH_INTERNAL_HEXDEC_HPP

#include <array>
#include <span>
#include <type_traits>

namespace cthash::internal {

consteval auto get_hexdec_table() noexcept {
	std::array<uint8_t, 128> result;

	auto char_to_hexdec = [](char c) {
		if (c >= '0' && c <= '9') {
			return static_cast<uint8_t>(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			return static_cast<uint8_t>(c - 'a' + 10u);
		} else if (c >= 'A' && c <= 'F') {
			return static_cast<uint8_t>(c - 'A' + 10u);
		} else {
			return static_cast<uint8_t>(0);
		}
	};

	for (int i = 0; i != static_cast<int>(result.size()); ++i) {
		result[i] = char_to_hexdec(static_cast<char>(i));
	}

	return result;
}

constexpr auto hexdec_alphabet = get_hexdec_table();

template <size_t N, typename CharT> constexpr auto hexdec_to_binary(std::span<const CharT, N * 2> in) -> std::array<std::byte, N> {
	return [in]<size_t... Idx>(std::index_sequence<Idx...>) {
		return std::array<std::byte, N>{static_cast<std::byte>(hexdec_alphabet[in[Idx * 2zu] & 0b0111'1111u] << 4u | hexdec_alphabet[in[Idx * 2zu + 1zu] & 0b0111'1111u])...};
	}
	(std::make_index_sequence<N>());
}

template <typename CharT, size_t N>
requires((N - 1zu) % 2zu == 0zu) // -1 because of zero terminator in literals
constexpr auto literal_hexdec_to_binary(const CharT (&in)[N]) -> std::array<std::byte, (N - 1zu) / 2> {
	return hexdec_to_binary<N / 2>(std::span<const char, N - 1zu>(in, N - 1zu));
}

} // namespace cthash::internal

#endif
