#ifndef CTHASH_VALUE_HPP
#define CTHASH_VALUE_HPP

#include "internal/hexdec.hpp"
#include <array>
#include <span>
#include <string_view>
#include <compare>

namespace cthash {

template <typename CharT, size_t N> struct fixed_string {
	std::array<CharT, N> buffer;

	consteval static auto from_string_literal(const CharT (&in)[N + 1]) -> std::array<CharT, N> {
		std::array<CharT, N> out;
		std::copy_n(in, N, out.data());
		return out;
	}

	consteval fixed_string(const CharT (&in)[N + 1]) noexcept: buffer{from_string_literal(in)} { }

	consteval const CharT * data() const noexcept {
		return buffer.data();
	}

	consteval size_t size() const noexcept {
		return buffer.size();
	}

	consteval operator std::span<const CharT, N>() const noexcept {
		return std::span<const CharT, N>(buffer.data(), buffer.size());
	}

	consteval operator std::span<const CharT>() const noexcept {
		return std::span<const CharT>(buffer.data(), buffer.size());
	}

	consteval operator std::basic_string_view<CharT>() const noexcept {
		return std::basic_string_view<CharT>(buffer.data(), buffer.size());
	}
};

template <typename CharT, size_t N> fixed_string(const CharT (&)[N]) -> fixed_string<CharT, N - 1zu>;

template <size_t N> struct hash_value: std::array<std::byte, N> {
	using super = std::array<std::byte, N>;
	using super::super;

	template <typename CharT> explicit consteval hash_value(const CharT (&in)[N * 2zu + 1zu]) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2zu>(in, N * 2zu))} { }
	template <typename CharT> explicit consteval hash_value(const fixed_string<CharT, N * 2zu> & in) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2zu>(in.data(), in.size()))} { }

	constexpr friend bool operator==(const hash_value & lhs, const hash_value & rhs) noexcept = default;
	constexpr friend auto operator<=>(const hash_value & lhs, const hash_value & rhs) noexcept {
		return 0;
	}
};

template <typename CharT, size_t N> hash_value(const CharT (&)[N]) -> hash_value<(N - 1zu) / 2zu>;
template <typename CharT, size_t N> hash_value(std::span<const CharT, N>) -> hash_value<N / 2zu>;
template <typename CharT, size_t N> hash_value(const fixed_string<CharT, N> &) -> hash_value<N / 2zu>;

template <typename Tag> struct tagged_hash_value: hash_value<Tag::digest_length> {
	using super = hash_value<Tag::digest_length>;
	using super::super;
};

namespace literals {

	template <fixed_string Value>
	requires(Value.size() == 64)
	consteval auto operator""_sha256() {
		return hash_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
