#ifndef CTHASH_ENCODING_BASE_HPP
#define CTHASH_ENCODING_BASE_HPP

#include "chunk-of-bits.hpp"
#include "encodings.hpp"
#include <bit>

namespace cthash {

template <typename Encoding> struct encoding_properties {
	static constexpr size_t size = std::size(Encoding::alphabet) - 1u;
	static_assert(std::popcount(size) == 1u, "Size of encoding's alphabet must be power-of-two");

	static constexpr size_t bits = std::countr_zero(size);

	static constexpr bool has_padding = padded_encoding<Encoding>;

	static constexpr char padding = [] {
		if constexpr (has_padding) {
			return Encoding::padding;
		} else {
			return '\0';
		}
	}();
};

template <typename Encoding, typename CharT, typename R> struct encode_to_view {
	using properties = encoding_properties<Encoding>;
	using chunk_view = cthash::chunk_of_bits_view<properties::bits, properties::has_padding, R>;

	struct sentinel {
		[[no_unique_address]] chunk_view::sentinel end;
	};

	template <bool Const> struct iterator {
		using difference_type = intptr_t;
		using value_type = CharT;

		chunk_view::template iterator<Const> it;

		constexpr iterator & operator++() noexcept {
			++it;
			return *this;
		}
		constexpr iterator operator++(int) noexcept {
			auto copy = *this;
			++it;
			return copy;
		}

		constexpr value_type operator*() const noexcept {
			const auto tmp = *it;
			if constexpr (!chunk_view::aligned) {
				// TODO: do without condition
				if (tmp.is_padding()) {
					return properties::padding;
				}
			}
			return static_cast<value_type>(Encoding::alphabet[static_cast<unsigned>(tmp.value)]);
		}

		constexpr friend bool operator==(const iterator &, const iterator &) noexcept = default;

		constexpr friend bool operator==(const iterator & lhs, const sentinel & rhs) noexcept {
			return lhs.it == rhs.end;
		}
	};

	chunk_view input;

	constexpr encode_to_view(R _input): input{_input} { }

	constexpr auto begin() const noexcept {
		return iterator<true>{input.begin()};
	}

	constexpr auto begin() noexcept {
		return iterator<false>{input.begin()};
	}

	constexpr auto end() const noexcept {
		return sentinel{input.end()};
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<R>) {
		return input.size();
	}

	constexpr auto to_string() const requires(std::ranges::sized_range<R>) {
#if __cpp_lib_ranges_to_container >= 202202L
		return std::ranges::to<std::basic_string<CharT>>(*this);
#else
		auto result = std::basic_string<CharT>{};
		result.resize(size());
		auto [i, o] = std::ranges::copy(begin(), end(), result.begin());
		assert(i == result.end());
		assert(o == result.end());
		return result;
#endif
	}

	constexpr friend std::basic_ostream<CharT> & operator<<(std::basic_ostream<CharT> & out, encode_to_view in) {
		std::ranges::copy(in.begin(), in.end(), std::ostream_iterator<CharT, CharT>(out));
		return out;
	}
};

template <typename Encoding, typename ValueT, typename R> struct decode_from_view {
	R input;

	template <bool Const> struct iterator { };
	struct sentinel { };

	constexpr decode_from_view(R _input): input{_input} { }

	constexpr auto begin() const noexcept {
		return iterator<true>{input.begin()};
	}

	constexpr auto begin() noexcept {
		return iterator<false>{input.begin()};
	}

	constexpr auto end() const noexcept {
		return sentinel{input.end()};
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<R>) {
		return input.size();
	}
};

template <typename Encoding, typename CharT = char> struct encode_to_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, encode_to_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) const {
		return encode_to_view<Encoding, CharT, R>(std::forward<R>(input));
	}
};

template <typename Encoding, typename ValueT = unsigned char> struct decode_from_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, decode_from_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) const {
		return decode_from_view<Encoding, ValueT, R>(std::forward<R>(input));
	}
};

template <typename Encoding, typename CharT = char> constexpr auto encode_to = encode_to_action<Encoding, CharT>{};
template <typename Encoding, typename ValueT = unsigned char> constexpr auto decode_from = decode_from_action<Encoding, ValueT>{};

constexpr auto binary_encode = encode_to<encoding::base2, char>;
constexpr auto base2_encode = encode_to<encoding::base2, char>;
constexpr auto base4_encode = encode_to<encoding::base4, char>;
constexpr auto base8_encode = encode_to<encoding::base8, char>;
constexpr auto octal_encode = encode_to<encoding::base8, char>;
constexpr auto hexdec_encode = encode_to<encoding::base16, char>;
constexpr auto hexdec_uppercase_encode = encode_to<encoding::base16_uppercase, char>;
constexpr auto base16_encode = encode_to<encoding::base16, char>;
constexpr auto base32_encode = encode_to<encoding::base32, char>;
constexpr auto base32_no_padding_encode = encode_to<encoding::base32_no_padding, char>;
constexpr auto z_base32_encode = encode_to<encoding::z_base32, char>;
constexpr auto base64_encode = encode_to<encoding::base64, char>;
constexpr auto base64url_encode = encode_to<encoding::base64url, char>;
constexpr auto base64_no_padding_encode = encode_to<encoding::base64_no_padding, char>;

constexpr auto binary_decode = decode_from<encoding::base2, char>;
constexpr auto base2_decode = decode_from<encoding::base2, char>;
constexpr auto base4_decode = decode_from<encoding::base4, char>;
constexpr auto base8_decode = decode_from<encoding::base8, char>;
constexpr auto hexdec_decode = decode_from<encoding::base16, char>;
constexpr auto base16_decode = decode_from<encoding::base16, char>;
constexpr auto base32_decode = decode_from<encoding::base32, char>;
constexpr auto z_base32_decode = decode_from<encoding::z_base32, char>;
constexpr auto base64_decode = decode_from<encoding::base64, char>;
constexpr auto base64url_decode = decode_from<encoding::base64url, char>;
constexpr auto base64_no_padding_decode = decode_from<encoding::base64_no_padding, char>;

} // namespace cthash

namespace std {

#if __cpp_lib_format >= 201907L
#define CTHASH_STDFMT_AVAILABLE 1
#endif

// template <typename Encoding, typename CharT, typename R> struct encode_to_view

#ifdef CTHASH_STDFMT_AVAILABLE
template <typename Encoding, typename R, typename CharT>
struct formatter<cthash::encode_to_view<Encoding, CharT, R>, CharT> {
	using subject_type = cthash::encode_to_view<Encoding, CharT, R>;

	template <typename ParseContext> constexpr auto parse(ParseContext & ctx) {
		return std::ranges::begin(ctx);
	}

	template <typename FormatContext> constexpr auto format(const subject_type & value, FormatContext & ctx) const {
		return std::ranges::copy(value, ctx.out()).out;
	}
};

#endif

} // namespace std

#endif
