#ifndef CTHASH_VALUE_HPP
#define CTHASH_VALUE_HPP

#include "internal/algorithm.hpp"
#include "internal/fixed-string.hpp"
#include "internal/hexdec.hpp"
#include <array>
#include <span>
#include <string_view>
#include <compare>

namespace cthash {

template <typename> struct identify;

template <size_t N> struct hash_value: std::array<std::byte, N> {
	using super = std::array<std::byte, N>;

	constexpr hash_value() noexcept: super{} { }
	explicit constexpr hash_value(super && s) noexcept: super(s) { }
	template <typename CharT> explicit constexpr hash_value(const CharT (&in)[N * 2u + 1u]) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2u>(in, N * 2u))} { }
	template <typename CharT> explicit constexpr hash_value(const internal::fixed_string<CharT, N * 2u> & in) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2u>(in.data(), in.size()))} { }

	// comparison support
	constexpr friend bool operator==(const hash_value & lhs, const hash_value & rhs) noexcept = default;
	constexpr friend auto operator<=>(const hash_value & lhs, const hash_value & rhs) noexcept -> std::strong_ordering {
		return internal::threeway_compare_of_same_size(lhs.data(), rhs.data(), N);
	}

	// print to ostream support
	template <typename CharT, typename Traits> constexpr friend auto & operator<<(std::basic_ostream<CharT, Traits> & os, const hash_value & val) {
		return internal::push_to_stream_as<internal::byte_hexdec_value>(val.begin(), val.end(), os);
	}
};

template <typename CharT, size_t N> hash_value(const CharT (&)[N]) -> hash_value<(N - 1u) / 2u>;
template <typename CharT, size_t N> hash_value(std::span<const CharT, N>) -> hash_value<N / 2u>;
template <typename CharT, size_t N> hash_value(const internal::fixed_string<CharT, N> &) -> hash_value<N / 2u>;

template <typename Tag> struct tagged_hash_value: hash_value<Tag::digest_length> {
	static constexpr size_t N = Tag::digest_length;

	using super = hash_value<Tag::digest_length>;
	using super::super;
	template <typename CharT> explicit constexpr tagged_hash_value(const internal::fixed_string<CharT, N * 2u> & in) noexcept: super{in} { }

	static constexpr size_t digest_length = Tag::digest_length;
};

namespace literals {

	template <internal::fixed_string Value>
	constexpr auto operator""_hash() {
		return hash_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
