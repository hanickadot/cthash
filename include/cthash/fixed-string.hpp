#ifndef CTHASH_FIXED_STRING_HPP
#define CTHASH_FIXED_STRING_HPP

#include <algorithm>
#include <span>
#include <string_view>

namespace cthash {

template <typename CharT, size_t N> struct fixed_string: std::array<CharT, N> {
	using super = std::array<CharT, N>;

	consteval static auto from_string_literal(const CharT (&in)[N + 1]) -> std::array<CharT, N> {
		std::array<CharT, N> out;
		std::copy_n(in, N, out.data());
		return out;
	}

	explicit constexpr fixed_string(std::nullptr_t) noexcept: super{} { }

	consteval fixed_string(const CharT (&in)[N + 1]) noexcept: super{from_string_literal(in)} { }

	using super::data;
	using super::size;

	constexpr operator std::span<const CharT, N>() const noexcept {
		return std::span<const CharT, N>(data(), size());
	}

	constexpr operator std::span<const CharT>() const noexcept {
		return std::span<const CharT>(data(), size());
	}

	constexpr operator std::basic_string_view<CharT>() const noexcept {
		return std::basic_string_view<CharT>(data(), size());
	}

	constexpr friend bool operator==(const fixed_string &, const fixed_string &) noexcept = default;
	constexpr friend bool operator==(const fixed_string & lhs, std::basic_string_view<CharT> rhs) noexcept {
		return std::basic_string_view<CharT>{lhs} == rhs;
	}
	constexpr friend bool operator==(const fixed_string & lhs, const CharT * rhs) noexcept {
		return std::basic_string_view<CharT>{lhs} == std::basic_string_view<CharT>{rhs};
	}
};

template <typename CharT, size_t N> fixed_string(const CharT (&)[N]) -> fixed_string<CharT, N - 1>;

} // namespace cthash

#endif
