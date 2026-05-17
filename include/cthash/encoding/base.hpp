#ifndef CTHASH_ENCODING_BASE_HPP
#define CTHASH_ENCODING_BASE_HPP

#include "chunk-of-bits.hpp"
#include "encodings.hpp"
#include <bit>
#include <iostream>

namespace cthash {

struct a_character_type {
	char value;
	constexpr a_character_type() noexcept = default;
	constexpr a_character_type(character auto v) noexcept: value{static_cast<char>(static_cast<unsigned char>(v))} {
		// whatever
	}
	constexpr a_character_type(const a_character_type &) noexcept = default;
	constexpr a_character_type(a_character_type &&) noexcept = default;
	constexpr a_character_type & operator=(const a_character_type &) noexcept = default;
	constexpr a_character_type & operator=(a_character_type &&) noexcept = default;

	template <character T> constexpr operator T() const noexcept {
		return static_cast<T>(value);
	}
	template <typename CharT> constexpr friend std::basic_ostream<CharT> & operator<<(std::basic_ostream<CharT> & out, a_character_type val) {
		return out << CharT{val};
	}
};

struct a_byte_type {
	std::byte value;
	constexpr a_byte_type() noexcept = default;
	constexpr a_byte_type(byte auto v) noexcept: value{static_cast<std::byte>(static_cast<unsigned char>(v))} {
		// whatever
	}
	constexpr a_byte_type(const a_byte_type &) noexcept = default;
	constexpr a_byte_type(a_byte_type &&) noexcept = default;
	constexpr a_byte_type & operator=(const a_byte_type &) noexcept = default;
	constexpr a_byte_type & operator=(a_byte_type &&) noexcept = default;

	template <byte T> constexpr operator T() const noexcept {
		return static_cast<T>(value);
	}
};

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

	static constexpr auto reverse_table = [] {
		translation_table output{};
		output.insert_alphabet(Encoding::alphabet);
		if constexpr (requires { Encoding::alt_alphabet; }) {
			output.insert_alphabet(Encoding::alt_alphabet);
		}
		return output;
	}();

	static constexpr uint8_t convert(a_character_type in) noexcept {
		return reverse_table.data[static_cast<unsigned char>(in.value)];
	}

	static constexpr bool is_padding(a_character_type in) noexcept requires(has_padding) {
		return (in.value == Encoding::padding);
	}
};

template <typename T> concept has_conversion = requires {
	{ T::convert('a') } -> std::convertible_to<a_byte_type>;
};

template <typename> struct identify;

template <auto Encoding, typename R, typename ByteT = a_byte_type> struct decode_view {
	using properties = encoding_properties<decltype(Encoding)>;
	// output is 8
	// input depends on the encoding
	using chunk_view = cthash::chunk_of_bits_view<8, properties::has_padding, R, properties::bits, properties>;
	using input_value_type = std::ranges::range_value_t<R>;

	struct sentinel {
		[[no_unique_address]] chunk_view::sentinel end;
	};

	template <bool Const> struct iterator {
		using difference_type = intptr_t;
		using value_type = ByteT;

		chunk_view::template iterator<Const> it;
		// identify<typename chunk_view::template iterator<Const>> x;

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
			return static_cast<value_type>((*it).value);
		}

		constexpr friend bool operator==(const iterator &, const iterator &) noexcept = default;

		constexpr friend bool operator==(const iterator & lhs, const sentinel & rhs) noexcept {
			return lhs.it == rhs.end;
		}
	};

	chunk_view input;

	constexpr decode_view(R && _input): input{std::forward<R>(_input)} { }

	constexpr auto begin() const noexcept {
		return iterator<true>{input.begin()};
	}

	constexpr auto begin() noexcept {
		return iterator<false>{input.begin()};
	}

	constexpr auto end() const noexcept {
		return sentinel{input.end()};
	}

	constexpr size_t size() const noexcept {
		return input.size();
	}
};

template <auto Encoding, typename ByteT = a_byte_type> struct decode_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, decode_action action) requires(character<std::ranges::range_value_t<R>>) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) const requires(character<std::ranges::range_value_t<R>>) {
		return decode_view<Encoding, R, ByteT>(std::forward<R>(input));
	}
};

template <typename Encoding, typename R, typename CharT = a_character_type> struct encode_view {
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

	constexpr encode_view(R && _input): input{std::forward<R>(_input)} { }

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

	template <typename StrCharT = CharT, typename Traits = std::char_traits<StrCharT>> constexpr auto to_string() const requires(std::ranges::sized_range<R>) {
		using result_type = std::basic_string<StrCharT, Traits>;
#if __cpp_lib_ranges_to_container >= 202202L
		return std::ranges::to<result_type>(*this);
#else
		auto result = result_type{};
		result.resize(size());
		auto [i, o] = std::ranges::copy(begin(), end(), result.begin());
		assert(i == result.end());
		assert(o == result.end());
		return result;
#endif
	}

	template <typename StrCharT> constexpr friend std::basic_ostream<StrCharT> & operator<<(std::basic_ostream<StrCharT> & out, encode_view in) {
		std::ranges::copy(in.begin(), in.end(), std::ostream_iterator<CharT>(out));
		return out;
	}
};

template <typename Encoding = void, typename CharT = a_character_type>
struct encode_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, encode_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) const {
		return encode_view<Encoding, R, CharT>(std::forward<R>(input));
	}
};

// just aliases to existing encodings
static constexpr auto base2 = encoding::base2{};
static constexpr auto binary = encoding::base2{};
static constexpr auto base4 = encoding::base4{};
static constexpr auto base8 = encoding::base8{};
static constexpr auto octal = encoding::base8{};
static constexpr auto base8_no_padding = encoding::base8_no_padding{};
static constexpr auto octal_no_padding = encoding::base8_no_padding{};
static constexpr auto base16 = encoding::base16{};
static constexpr auto base16_uppercase = encoding::base16_uppercase{};
static constexpr auto hexdec = encoding::base16{};
static constexpr auto hexdec_uppercase = encoding::base16_uppercase{};
static constexpr auto base32 = encoding::base32{};
static constexpr auto base32_no_padding = encoding::base32_no_padding{};
static constexpr auto z_base32 = encoding::z_base32{};
static constexpr auto base64 = encoding::base64{};
static constexpr auto base64url = encoding::base64url{};
static constexpr auto base64_no_padding = encoding::base64_no_padding{};

static constexpr auto unknown = encoding::unknown{};

// encoding / decoding interface

template <typename CharT = a_character_type, encoding_type T> consteval auto encode(T) {
	return encode_action<T, CharT>{};
}

template <typename CharT = a_byte_type, encoding_type T> consteval auto decode(T) {
	return decode_action<T{}, CharT>{};
}

// for compatibility with the old API
constexpr auto binary_encode = encode_action<encoding::base2, char>{};
constexpr auto base2_encode = encode_action<encoding::base2, char>{};
constexpr auto base4_encode = encode_action<encoding::base4, char>{};
constexpr auto base8_encode = encode_action<encoding::base8, char>{};
constexpr auto octal_encode = encode_action<encoding::base8, char>{};
constexpr auto base8_no_padding_encode = encode_action<encoding::base8_no_padding, char>{};
constexpr auto octal_no_padding_encode = encode_action<encoding::base8_no_padding, char>{};
constexpr auto hexdec_encode = encode_action<encoding::base16, char>{};
constexpr auto hexdec_uppercase_encode = encode_action<encoding::base16_uppercase, char>{};
constexpr auto base16_encode = encode_action<encoding::base16, char>{};
constexpr auto base32_encode = encode_action<encoding::base32, char>{};
constexpr auto base32_no_padding_encode = encode_action<encoding::base32_no_padding, char>{};
constexpr auto z_base32_encode = encode_action<encoding::z_base32, char>{};
constexpr auto base64_encode = encode_action<encoding::base64, char>{};
constexpr auto base64url_encode = encode_action<encoding::base64url, char>{};
constexpr auto base64_no_padding_encode = encode_action<encoding::base64_no_padding, char>{};

// same here
template <typename Encoding, typename CharT = char> constexpr auto encode_to = encode_action<Encoding, CharT>{};
template <typename Encoding, typename ByteT = std::byte> constexpr auto decode_from = decode_action<Encoding{}, ByteT>{};

} // namespace cthash

namespace std {

#if __cpp_lib_format >= 201907L
#define CTHASH_STDFMT_AVAILABLE 1
#endif

// template <typename Encoding, typename CharT, typename R> struct encode_view

#ifdef CTHASH_STDFMT_AVAILABLE
template <typename Encoding, typename R, typename CharT>
struct formatter<cthash::encode_view<Encoding, R>, CharT> {
	using subject_type = cthash::encode_view<Encoding, R>;

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
