#ifndef CTHASH_VALUE_HPP
#define CTHASH_VALUE_HPP

#include "fixed-string.hpp"
#include "encoding/base.hpp"
#include "encoding/encodings.hpp"
#include "internal/algorithm.hpp"
#include "internal/deduce.hpp"
#include "internal/hexdec.hpp"
#include <algorithm>
#include <array>
#include <format>
#include <span>
#include <string_view>
#include <compare>

namespace cthash {

// hash_value

template <size_t N> struct hash_value: std::array<std::byte, N> {
	using super = std::array<std::byte, N>;

	constexpr hash_value() noexcept: super{} { }
	explicit constexpr hash_value(super && s) noexcept: super(s) { }
	template <typename CharT> explicit constexpr hash_value(const CharT (&in)[N * 2u + 1u]) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2u>(in, N * 2u))} { }
	template <typename CharT> explicit constexpr hash_value(const fixed_string<CharT, N * 2u> & in) noexcept: super{internal::hexdec_to_binary<N>(std::span<const CharT, N * 2u>(in.data(), in.size()))} { }

	// comparison support
	constexpr friend bool operator==(const hash_value & lhs, const hash_value & rhs) noexcept = default;
	constexpr friend auto operator<=>(const hash_value & lhs, const hash_value & rhs) noexcept -> std::strong_ordering {
		return internal::threeway_compare_of_same_size(lhs.data(), rhs.data(), N);
	}

	template <typename Encoding = cthash::encoding::hexdec, typename CharT, typename Traits> constexpr auto & print_into(std::basic_ostream<CharT, Traits> & os) const {
		auto hexdec_view = *this | cthash::encode_to<Encoding, CharT>;
		std::ranges::copy(hexdec_view, std::ostream_iterator<CharT, CharT>(os));
		return os;
	}

	// print to ostream support
	template <typename CharT, typename Traits> constexpr friend auto & operator<<(std::basic_ostream<CharT, Traits> & os, const hash_value & val) {
		return val.print_into(os);
	}

	template <size_t PrefixN> constexpr auto prefix() const noexcept requires(PrefixN <= N) {
		hash_value<PrefixN> output{};
		std::ranges::copy(this->begin(), this->begin() + PrefixN, output.begin());
		return output;
	}

	template <size_t SuffixN> constexpr auto suffix() const noexcept requires(SuffixN <= N) {
		hash_value<SuffixN> output{};
		std::ranges::copy(this->end() - SuffixN, this->end(), output.begin());
		return output;
	}
	template <typename Encoding = cthash::encoding::hexdec, typename CharT = char> constexpr friend auto to_string(const hash_value & value) {
		const auto encoded = value | cthash::encode_to<Encoding, CharT>;
#if __cpp_lib_ranges_to_container >= 202202L
		return std::ranges::to<std::basic_string<CharT>>(encoded);
#else
		auto result = std::basic_string<CharT>{};
		result.resize(encoded.size());
		auto [i, o] = std::ranges::copy(encoded.begin(), encoded.end(), result.begin());
		assert(i == encoded.end());
		assert(o == result.end());
		return result;
#endif
	}
	template <typename Encoding = cthash::encoding::hexdec, typename CharT = char> constexpr friend auto to_fixed_string(const hash_value & value) {
		const auto encoded = value | cthash::encode_to<Encoding, CharT>;
		// it's type dependendent so we can calculate the size...
		constexpr size_t size_needed = (hash_value{} | cthash::encode_to<Encoding, CharT>).size();

		auto result = cthash::fixed_string<CharT, size_needed>{nullptr};

		auto [i, o] = std::ranges::copy(encoded.begin(), encoded.end(), result.begin());
		assert(i == encoded.end());
		assert(o == result.end());

		return result;
	}
};

template <typename CharT, size_t N> hash_value(const CharT (&)[N]) -> hash_value<(N - 1u) / 2u>;
template <typename CharT, size_t N> hash_value(std::span<const CharT, N>) -> hash_value<N / 2u>;
template <typename CharT, size_t N> hash_value(const fixed_string<CharT, N> &) -> hash_value<N / 2u>;

template <typename> struct default_encoding {
	using encoding = cthash::encoding::hexdec;
};

template <typename Tag> concept tag_with_encoding = requires() {
	typename Tag::encoding;
};

template <tag_with_encoding Tag> struct default_encoding<Tag> {
	using encoding = Tag::encoding;
};

template <typename Tag, size_t = internal::digest_bytes_length_of<Tag>> struct tagged_hash_value: hash_value<internal::digest_bytes_length_of<Tag>> {
	static constexpr size_t N = internal::digest_bytes_length_of<Tag>;

	using super = hash_value<N>;
	using super::super;
	template <typename CharT> explicit constexpr tagged_hash_value(const fixed_string<CharT, N * 2u> & in) noexcept: super{in} { }

	static constexpr size_t digest_length = N;

	template <typename Encoding = default_encoding<Tag>::encoding, typename CharT, typename Traits> constexpr auto & print_into(std::basic_ostream<CharT, Traits> & os) const {
		return super::template print_into<Encoding>(os);
	}

	template <typename CharT, typename Traits> constexpr friend auto & operator<<(std::basic_ostream<CharT, Traits> & os, const tagged_hash_value & val) {
		return val.print_into(os);
	}

	template <typename Encoding = typename cthash::default_encoding<Tag>::encoding, typename CharT = char> constexpr friend auto to_string(const tagged_hash_value & value) {
		return to_string<Encoding, CharT>(static_cast<const super &>(value));
	}

	template <typename Encoding = typename cthash::default_encoding<Tag>::encoding, typename CharT = char> constexpr friend auto to_fixed_string(const tagged_hash_value & value) {
		return to_fixed_string<Encoding, CharT>(static_cast<const super &>(value));
	}
};

template <typename T> concept variable_digest_length = T::digest_length_bit == 0u;

template <size_t N, variable_digest_length Tag> struct variable_bit_length_tag: Tag {
	static constexpr size_t digest_length_bit = N;
};

template <typename T> concept convertible_to_tagged_hash_value = requires(const T & obj) {
	{ tagged_hash_value{obj} };
};

namespace literals {

	template <fixed_string Value>
	constexpr auto operator""_hash() {
		return hash_value(Value);
	}

} // namespace literals

} // namespace cthash

namespace std {

#if __cpp_lib_format >= 201907L
#define CTHASH_STDFMT_AVAILABLE 1
#endif

#if _LIBCPP_VERSION >= 170000
// libc++ will define __cpp_lib_format macro in 19.0
// https://github.com/llvm/llvm-project/issues/77773
#define CTHASH_STDFMT_AVAILABLE 1
#endif

#ifdef CTHASH_STDFMT_AVAILABLE
template <size_t N, typename CharT>
struct formatter<cthash::hash_value<N>, CharT> {
	using subject_type = cthash::hash_value<N>;
	using default_encoding = cthash::encoding::hexdec;

	cthash::runtime_encoding encoding{default_encoding{}};

	template <typename ParseContext> constexpr auto parse(ParseContext & ctx) {
		auto [enc, out] = cthash::select_encoding<cthash::runtime_encoding, default_encoding>(ctx);
		this->encoding = enc;
		return out;
	}

	template <typename FormatContext> constexpr auto format(const subject_type & value, FormatContext & ctx) const {
		return encoding.visit([&]<typename SelectedEncoding>(SelectedEncoding) {
			return std::ranges::copy(value | cthash::encode_to<SelectedEncoding, CharT>, ctx.out()).out;
		});
	}
};

template <typename Tag, size_t N, typename CharT>
struct formatter<cthash::tagged_hash_value<Tag, N>, CharT> {
	using subject_type = cthash::tagged_hash_value<Tag, N>;
	using default_encoding = typename cthash::default_encoding<Tag>::encoding;

	cthash::runtime_encoding encoding{default_encoding{}};

	template <typename ParseContext> constexpr auto parse(ParseContext & ctx) {
		auto [enc, out] = cthash::select_encoding<cthash::runtime_encoding, default_encoding>(ctx);
		this->encoding = enc;
		return out;
	}

	template <typename FormatContext> constexpr auto format(const subject_type & value, FormatContext & ctx) const {
		return encoding.visit([&]<typename SelectedEncoding>(SelectedEncoding) {
			return std::ranges::copy(value | cthash::encode_to<SelectedEncoding, CharT>, ctx.out()).out;
		});
	}
};

template <cthash::convertible_to_tagged_hash_value Type, typename CharT> struct formatter<Type, CharT>: formatter<decltype(cthash::tagged_hash_value{std::declval<Type>()}), CharT> {
};

#endif

} // namespace std

#endif
