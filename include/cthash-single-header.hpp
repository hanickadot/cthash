#ifndef CTHASH_CTHASH_HPP
#define CTHASH_CTHASH_HPP

// SHA-2 family
#ifndef CTHASH_SHA2_SHA224_HPP
#define CTHASH_SHA2_SHA224_HPP

#ifndef CTHASH_SHA2_SHA256_HPP
#define CTHASH_SHA2_SHA256_HPP

#ifndef CTHASH_SHA2_COMMON_HPP
#define CTHASH_SHA2_COMMON_HPP

#ifndef CONSTEXPR_SHA2_HASHER_HPP
#define CONSTEXPR_SHA2_HASHER_HPP

#ifndef CTHASH_SIMPLE_HPP
#define CTHASH_SIMPLE_HPP

#include <utility>

namespace cthash {

template <typename Hasher, typename In, typename... Args> concept hasher_like = requires(Hasher & h, const In & in, Args &&... args) //
{
	{ Hasher{std::forward<Args>(args)...} };
	{ h.update(in) } -> std::same_as<Hasher &>;
	{ h.final() };
};

template <typename Hasher, typename In> concept direct_hasher = requires(Hasher & h, const In & in) //
{
	{ h.update_and_final(in) };
};

template <typename Hasher, typename T, typename... Args>
requires hasher_like<Hasher, T, Args...>
constexpr auto simple(const T & value, Args &&... args) noexcept {
	if constexpr (direct_hasher<Hasher, T>) {
		return Hasher{std::forward<Args>(args)...}.update_and_final(value);
	} else {
		return Hasher{std::forward<Args>(args)...}.update(value).final();
	}
}

} // namespace cthash

#endif

#ifndef CTHASH_VALUE_HPP
#define CTHASH_VALUE_HPP

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

#ifndef CTHASH_ENCODING_BASE_HPP
#define CTHASH_ENCODING_BASE_HPP

#ifndef CTHASH_ENCODING_CHUNK_OF_BITS_HPP
#define CTHASH_ENCODING_CHUNK_OF_BITS_HPP

#ifndef CTHASH_ENCODING_BIT_BUFFER_HPP
#define CTHASH_ENCODING_BIT_BUFFER_HPP

#ifndef CTHASH_ENCODING_CONCEPTS_HPP
#define CTHASH_ENCODING_CONCEPTS_HPP

#include <ranges>
#include <concepts>

namespace cthash {

template <auto Value> struct fixed { };
template <auto Value> constexpr auto fixed_cast = fixed<Value>{};

template <typename T, typename... Types> concept one_of = (std::same_as<T, Types> || ...);

template <typename T> concept byte = one_of<std::remove_cvref_t<T>, char, unsigned char, signed char, uint8_t, int8_t, std::byte>;

template <typename Encoding> concept padded_encoding = requires() {
	{ Encoding::padding } -> cthash::byte;
};

template <typename T> concept byte_range = requires() {
	requires std::ranges::range<T>;
	requires cthash::byte<std::ranges::range_value_t<T>>;
};

} // namespace cthash

#endif

#include <bit>
#include <iostream>
#include <numeric>
#include <ranges>
#include <cassert>
#include <concepts>
#include <cstdint>

namespace cthash {

template <size_t Bits> struct select_bit_integer;

template <size_t Bits> requires(Bits <= 8) struct select_bit_integer<Bits> {
	using type = uint8_t;
};

template <size_t Bits> requires(Bits > 8 && Bits <= 16) struct select_bit_integer<Bits> {
	using type = uint16_t;
};

template <size_t Bits> requires(Bits > 16 && Bits <= 32) struct select_bit_integer<Bits> {
	using type = uint32_t;
};

template <size_t Bits> requires(Bits > 32 && Bits <= 64) struct select_bit_integer<Bits> {
	using type = uint64_t;
};

template <size_t Bits> using select_bit_integer_t = select_bit_integer<Bits>::type;

template <size_t V> requires(std::popcount(V) == 1u) constexpr auto log2_of_power_of_2 = static_cast<size_t>(std::countr_zero(V));

template <size_t Bits> constexpr auto mask = static_cast<select_bit_integer_t<Bits>>((static_cast<select_bit_integer_t<Bits>>(1u) << Bits) - 1u);

template <size_t Capacity> class basic_bit_buffer {
public:
	static constexpr auto capacity = std::integral_constant<size_t, Capacity>{};
	using storage_type = select_bit_integer_t<capacity()>;
	using size_type = select_bit_integer_t<log2_of_power_of_2<std::bit_ceil(capacity())>>;

public:
	storage_type buffer{0};
	size_type bits_available{0};

public:
	template <size_t Bits> static constexpr auto mask = static_cast<storage_type>((static_cast<storage_type>(1u) << Bits) - 1u);

	constexpr friend bool operator==(const basic_bit_buffer & lhs, const basic_bit_buffer & rhs) noexcept = default;

	constexpr size_type size() const noexcept {
		return bits_available;
	}

	constexpr size_type unused_size() const noexcept {
		return capacity() - bits_available;
	}

	constexpr bool empty() const noexcept {
		return bits_available == 0u;
	}

	constexpr bool full() const noexcept {
		return bits_available == capacity();
	}

	template <size_t Bits> constexpr void push(select_bit_integer_t<Bits> in) noexcept requires(Bits <= capacity()) {
		assert(size() <= capacity() - Bits);
		buffer = static_cast<storage_type>(buffer << Bits) | static_cast<storage_type>(in);
		bits_available += static_cast<size_type>(Bits);
	}
	constexpr void push_empty_bits(size_t count) noexcept {
		buffer = static_cast<storage_type>(buffer << count);
		bits_available += static_cast<unsigned char>(count);
	}

	template <size_t Bits> constexpr void pop() noexcept requires(Bits <= capacity()) {
		assert(size() >= Bits);
		bits_available -= static_cast<size_type>(Bits);
	}

	template <size_t Bits> constexpr auto front() const noexcept -> select_bit_integer_t<Bits> requires(Bits <= capacity()) {
		using output_type = select_bit_integer_t<Bits>;
		assert(size() >= static_cast<size_type>(Bits));
		return static_cast<output_type>((buffer >> (bits_available - Bits))) & mask<Bits>;
	}
};

constexpr size_t calculate_padding_bit_count(size_t number_of_bits_in_buffer, size_t output_size, size_t input_size) {
	size_t n = number_of_bits_in_buffer;
	size_t padding_bits = 0u;

	while (n != 0u) {
		padding_bits += input_size;
		n += input_size;

		while (n >= output_size) {
			n = n - output_size;
		}
	}

	return padding_bits;
}

template <size_t OutBits, size_t InBits = 8u> class bit_buffer: protected basic_bit_buffer<std::lcm(OutBits, InBits)> {
	using super = basic_bit_buffer<std::lcm(OutBits, InBits)>;

public:
	constexpr bit_buffer() noexcept = default;

	using typename super::size_type;
	static constexpr auto out_bits = std::integral_constant<size_type, OutBits>{};
	static constexpr auto in_bits = std::integral_constant<size_type, InBits>{};

	using out_type = select_bit_integer_t<OutBits>;
	using in_type = select_bit_integer_t<InBits>;

	using super::capacity;
	static constexpr auto in_capacity = std::integral_constant<size_type, (capacity() / in_bits())>{};
	static constexpr auto out_capacity = std::integral_constant<size_type, (capacity() / out_bits())>{};

	static constexpr auto aligned = std::bool_constant<capacity() == in_capacity()>{};

	constexpr void push(in_type in) noexcept {
		super::template push<in_bits>(in);
	}

	constexpr void push_empty() noexcept {
		this->push(in_type{0u});
	}

	constexpr size_type push_zeros_to_align() noexcept requires(aligned()) {
		return 0u;
	}

	constexpr size_type push_zeros_for_padding() noexcept requires(aligned()) {
		return 0u;
	}

	constexpr size_type push_zeros_to_align() noexcept requires(!aligned()) {
		if (empty()) {
			return 0u;
		}

		assert(out_bits > super::size());
		const size_type missing_bits = static_cast<size_type>(out_bits - super::size());
		super::push_empty_bits(missing_bits);
		return missing_bits;
	}

	constexpr size_type push_zeros_for_padding() noexcept requires(!aligned()) {
		const size_type usable_bits = super::size();
		const size_type missing_bits = static_cast<size_type>(calculate_padding_bit_count(super::size(), out_bits, in_bits));
		super::push_empty_bits(missing_bits);
		return usable_bits;
	}

	constexpr void pop() noexcept {
		super::template pop<out_bits>();
	}

	constexpr auto front() const noexcept -> out_type {
		return super::template front<out_bits>();
	}

	constexpr size_type size() const noexcept {
		return static_cast<size_type>(super::size() / out_bits);
	}

	constexpr size_type unused_size() const noexcept {
		return static_cast<size_type>(super::unused_size() / in_bits);
	}

	using super::empty;
	using super::full;

	constexpr bool has_bits_for_pop() const noexcept {
		return super::size() >= out_bits;
	}

	constexpr bool has_capacity_for_push() const noexcept {
		return super::size() <= (capacity() - in_bits);
	}
};

} // namespace cthash

#endif

#include <iostream>
#include <ranges>

namespace cthash {

template <typename Buffer> struct buffer_result_type;

template <typename Buffer> requires(Buffer::aligned()) struct buffer_result_type<Buffer> {
	typename Buffer::out_type value;
	static constexpr Buffer::size_type missing_bits = {0u};

	constexpr bool is_padding() const noexcept {
		return false;
	}
};

template <typename Buffer> requires(!Buffer::aligned()) struct buffer_result_type<Buffer> {
	typename Buffer::out_type value;
	typename Buffer::size_type missing_bits;

	constexpr bool is_padding() const noexcept {
		return missing_bits == Buffer::out_bits;
	}
};

template <typename Buffer, bool AllowPadding> struct buffer_with_missing_bits;

template <typename Buffer, bool AllowPadding> requires(Buffer::aligned()) struct buffer_with_missing_bits<Buffer, AllowPadding> {
	Buffer buffer{};

	struct result_type {
		typename Buffer::out_type value;
		static constexpr Buffer::size_type missing_bits = {0u};

		constexpr bool is_padding() const noexcept {
			return false;
		}
	};

	static constexpr bool aligned = Buffer::aligned();

	constexpr friend bool operator==(const buffer_with_missing_bits & lhs, const buffer_with_missing_bits & rhs) noexcept = default;

	constexpr auto front() const noexcept {
		return result_type{buffer.front()};
	}

	constexpr bool empty() const noexcept {
		return buffer.empty();
	}

	constexpr void pop() noexcept {
		return buffer.pop();
	}

	template <typename It, typename End> constexpr void feed_buffer(It & it, End end) noexcept {
		using input_value_type = std::iterator_traits<It>::value_type;

		while (!buffer.has_bits_for_pop() && (it != end)) {
			buffer.push(static_cast<std::make_unsigned_t<input_value_type>>(*it));
			++it;
		}
	}
};

template <typename Buffer, bool AllowPadding> requires(!Buffer::aligned()) struct buffer_with_missing_bits<Buffer, AllowPadding> {
	Buffer buffer{};
	Buffer::size_type missing_bits{0};

	static constexpr bool aligned = Buffer::aligned();

	struct result_type {
		typename Buffer::out_type value;
		typename Buffer::size_type missing_bits;

		constexpr bool is_padding() const noexcept {
			return missing_bits == Buffer::out_bits;
		}
	};

	constexpr friend bool operator==(const buffer_with_missing_bits & lhs, const buffer_with_missing_bits & rhs) noexcept = default;

	constexpr auto front() const noexcept {
		assert(Buffer::out_bits >= missing_bits);
		return result_type{buffer.front(), missing_bits};
	}

	constexpr bool empty() const noexcept {
		return buffer.empty();
	}

	constexpr void pop() noexcept {
		return buffer.pop();
	}

	constexpr void pad_buffer() noexcept requires(AllowPadding) {
		// full multi-chunk padding (for baseN encodings)
		missing_bits = (Buffer::out_bits - buffer.push_zeros_for_padding());
	}

	constexpr void pad_buffer() noexcept requires(!AllowPadding) {
		// only add enough zero to finish current output chunk
		missing_bits = buffer.push_zeros_to_align();
	}

	constexpr void saturate_missing_bits() noexcept requires(AllowPadding) {
		if (missing_bits) {
			missing_bits = Buffer::out_bits;
		}
		// missing_bits = static_cast<buffer_size_t>((unsigned)(bool)missing_bits * output_value_bit_size);
	}

	constexpr void saturate_missing_bits() noexcept requires(!AllowPadding) {
		// do nothing :)
	}

	template <typename It, typename End> constexpr void feed_buffer(It & it, End end) noexcept {
		using input_value_type = std::iterator_traits<It>::value_type;

		for (;;) {
			if (it == end) {
				if (buffer.has_bits_for_pop()) {
					// if this is second pass after padding we can mark all bits as missing
					saturate_missing_bits();
				} else {
					// fill remainder of buffer with zeros
					pad_buffer();
				}

				return;
			}

			if (buffer.has_bits_for_pop()) {
				return;
			}

			buffer.push(static_cast<std::make_unsigned_t<input_value_type>>(*it));
			++it;
		}
	}
};

template <bool Value> struct conditional;

template <> struct conditional<true> {
	template <typename T, typename> using type = T;
};

template <> struct conditional<false> {
	template <typename, typename T> using type = T;
};

template <bool Const, typename T> using maybe_const = typename conditional<Const>::template type<const T, T>;

template <typename T> concept integral_like = std::integral<T> || std::same_as<std::byte, T>;

template <size_t Bits, bool AllowPadding, std::ranges::input_range Input> requires integral_like<std::ranges::range_value_t<Input>> struct chunk_of_bits_view {
	using input_value_type = std::ranges::range_value_t<Input>;

	static constexpr size_t output_value_bit_size = Bits;
	static constexpr size_t input_value_bit_size = sizeof(input_value_type) * 8u;
	using buffer_t = cthash::bit_buffer<output_value_bit_size, input_value_bit_size>;
	using buffer_size_t = buffer_t::size_type;
	Input input;

	static constexpr bool aligned = buffer_t::aligned;

	struct sentinel { };

	template <bool Const> struct iterator {
		using parent = maybe_const<Const, Input>;
		using storage_type = buffer_with_missing_bits<buffer_t, AllowPadding>;
		using value_type = storage_type::result_type;
		using difference_type = intptr_t;

		std::ranges::iterator_t<parent> it;
		[[no_unique_address]] std::ranges::sentinel_t<parent> end;

		storage_type buffer{};

		constexpr iterator(parent & p) noexcept: it{p.begin()}, end{p.end()} {
			// initialize
			buffer.feed_buffer(it, end);
		}

		iterator(const iterator &) = default;
		iterator(iterator &&) = default;

		iterator & operator=(const iterator &) = default;
		iterator & operator=(iterator &&) = default;

		constexpr iterator & operator++() noexcept {
			buffer.pop();
			buffer.feed_buffer(it, end);
			return *this;
		}

		constexpr iterator operator++(int) noexcept {
			auto copy = *this;
			this->operator++();
			return copy;
		}

		constexpr auto operator*() const noexcept {
			return buffer.front();
		}

		constexpr friend bool operator==(const iterator & lhs, const iterator & rhs) noexcept = default;

		constexpr friend bool operator==(const iterator & self, sentinel) noexcept {
			return self.buffer.empty();
		}
	};

	static_assert(std::input_iterator<iterator<true>>);
	static_assert(std::input_iterator<iterator<false>>);
	static_assert(std::sentinel_for<sentinel, iterator<true>>);
	static_assert(std::sentinel_for<sentinel, iterator<false>>);

	constexpr chunk_of_bits_view(Input _input) noexcept: input{_input} { }

	constexpr auto begin() const noexcept {
		return iterator<true>{input};
	}

	constexpr auto begin() noexcept {
		return iterator<false>{input};
	}

	constexpr auto end() const noexcept {
		return sentinel{};
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<Input> && AllowPadding) {
		// calculate with blocks
		return ((std::ranges::size(input) + (buffer_t::in_capacity() - 1u)) / buffer_t::in_capacity()) * buffer_t::out_capacity();
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<Input> && !AllowPadding) {
		// calculate with bits
		const size_t bit_size_of_input = std::ranges::size(input) * input_value_bit_size;
		return (bit_size_of_input + (output_value_bit_size - 1u)) / output_value_bit_size;
	}
};

template <size_t Bits, bool AllowPadding> struct chunk_of_bits_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, chunk_of_bits_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) {
		return chunk_of_bits_view<Bits, AllowPadding, R>(std::forward<R>(input));
	}
};

template <size_t Bits, bool AllowPadding = false> constexpr auto chunk_of_bits = chunk_of_bits_action<Bits, AllowPadding>{};

} // namespace cthash

#endif

#ifndef CTHASH_ENCODING_ENCODINGS_HPP
#define CTHASH_ENCODING_ENCODINGS_HPP

#include <variant>

namespace cthash {

namespace encoding {

	template <typename...> struct list { };

	struct base64 {
		static constexpr std::string_view name = "base64";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		static constexpr char padding = '=';
	};

	struct base64_no_padding {
		static constexpr std::string_view name = "base64_no_padding";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	};

	struct base64url {
		static constexpr std::string_view name = "base64url";
		static constexpr std::string_view alt_name = "base64_url";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	};

	static_assert(padded_encoding<base64>);

	struct base32 {
		static constexpr std::string_view name = "base32";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		static constexpr char padding = '=';
	};

	struct base32_no_padding {
		static constexpr std::string_view name = "base32_no_padding";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	};

	struct z_base32 {
		static constexpr std::string_view name = "z_base32";
		static constexpr std::string_view alt_name = "zbase32";

		static constexpr char alphabet[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
	};

	struct base16 {
		static constexpr std::string_view name = "base16";
		static constexpr std::string_view alt_name = "hexdec";

		static constexpr char alphabet[] = "0123456789abcdef";
	};

	using hexdec = base16;

	struct base16_uppercase {
		static constexpr std::string_view name = "BASE16";
		static constexpr std::string_view alt_name = "HEXDEC";

		static constexpr char alphabet[] = "0123456789ABCDEF";
	};

	using hexdec_uppercase = base16_uppercase;

	struct base8 {
		static constexpr std::string_view name = "base8";
		static constexpr std::string_view alt_name = "octal";

		static constexpr char alphabet[] = "01234567";
		static constexpr char padding = '=';
	};

	using octal = base8;

	struct base4 {
		static constexpr std::string_view name = "base4";

		static constexpr char alphabet[] = "0123";
	};

	struct base2 {
		static constexpr std::string_view name = "base2";
		static constexpr std::string_view alt_name = "binary";

		static constexpr char alphabet[] = "01";
	};

	using binary = base2;

	using known_encodings = list<base64, base64_no_padding, base64url, base32, base32_no_padding, z_base32, base16, base16_uppercase, base8, base4, base2>;

} // namespace encoding

template <typename Defs> struct dynamic_encodings;

template <typename Encoding> concept has_alt_name = requires {
	{ Encoding::alt_name } -> std::same_as<const std::string_view &>;
};

static_assert(has_alt_name<encoding::hexdec>);

template <typename T, typename... Ts> concept one_from = (std::same_as<T, Ts> || ... || false);

template <typename Encoding> constexpr size_t longest_name_for = Encoding::name.size();
template <has_alt_name Encoding> constexpr size_t longest_name_for<Encoding> = std::max(Encoding::name.size(), Encoding::alt_name.size());

template <typename Encoding> constexpr bool match_encoding(std::string_view name) noexcept {
	return Encoding::name == name;
}

template <has_alt_name Encoding> constexpr bool match_encoding(std::string_view name) noexcept {
	return Encoding::name == name || Encoding::alt_name == name;
}

template <typename... List> struct dynamic_encodings<encoding::list<List...>>: std::variant<List...> {
	using super = std::variant<List...>;

	template <typename Encoding> static constexpr bool assign_encoding(std::string_view name, std::optional<super> & output) noexcept {
		auto r = match_encoding<Encoding>(name);

		if (!r) {
			return false;
		}

		output = Encoding{};
		return true;
	}

	static constexpr auto select_encoding(std::string_view name) -> super {
		std::optional<super> output{std::nullopt};

		// I'm not using bool to avoid warning to have better code coverage
		const auto success = (unsigned(assign_encoding<List>(name, output)) | ... | 0u);

		if (!success) {
			throw std::invalid_argument{"unknown encoding name"};
		}

		assert(output.has_value());

		return *output;
	}

	static constexpr size_t longest_name_size = std::max({longest_name_for<List>...});

	constexpr dynamic_encodings(std::string_view name): super(select_encoding(name)) { }
	constexpr dynamic_encodings(one_from<List...> auto enc) noexcept: super(enc) { }

	template <typename Fnc> constexpr auto visit(Fnc && fnc) const {
		return std::visit(std::forward<Fnc>(fnc), static_cast<const super &>(*this));
	}
};

template <typename Encoding, typename DefaultEncoding = encoding::hexdec, typename InputContext> constexpr auto select_encoding(InputContext && input) {
	using iterator_t = decltype(std::ranges::begin(input));

	struct result {
		Encoding encoding;
		iterator_t iterator;
	};

	auto it = std::ranges::begin(input);

	if (it == std::ranges::end(input) || *it == '}') {
		return result{.encoding = DefaultEncoding{}, .iterator = it};
	}

	// this will copy it into buffer to compare
	std::array<char, Encoding::longest_name_size> buffer{};
	auto out = buffer.begin();

	for (;;) {
		if (it == std::ranges::end(input)) {
			break;
		}

		const char c = *it;

		if (c == '}') {
			break;
		}

		if (out != buffer.end()) {
			*out++ = c;
		}

		++it;
	}

	const std::string_view name = std::string_view(buffer.data(), static_cast<size_t>(std::distance(buffer.begin(), out)));

	return result{.encoding = Encoding(name), .iterator = it};
}

using runtime_encoding = dynamic_encodings<encoding::known_encodings>;

template <typename DefaultEncoding = encoding::hexdec, typename InputContext> constexpr auto select_runtime_encoding(InputContext && input) {
	return select_encoding<runtime_encoding, DefaultEncoding>(std::forward<InputContext>(input));
}

} // namespace cthash

#endif

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
	template <std::ranges::input_range R> constexpr auto operator()(R && input) {
		return encode_to_view<Encoding, CharT, R>(std::forward<R>(input));
	}
};

template <typename Encoding, typename ValueT = unsigned char> struct decode_from_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, decode_from_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) {
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

#endif

#ifndef CTHASH_INTERNAL_ALGORITHM_HPP
#define CTHASH_INTERNAL_ALGORITHM_HPP

#include <numeric>
#include <compare>
#include <cstddef>
#include <cstdint>

namespace cthash::internal {

template <typename It1, typename It2> constexpr auto threeway_compare_of_same_size(It1 lhs, It2 rhs, size_t length) -> std::strong_ordering {
	for (size_t i = 0; i != length; ++i) {
		if (const auto r = (*lhs++ <=> *rhs++); r != 0) {
			return r;
		}
	}

	return std::strong_ordering::equal;
}

template <typename T, typename It1, typename It2, typename Stream> constexpr auto & push_to_stream_as(It1 f, It2 l, Stream & stream) {
	constexpr auto cast_and_shift = [](Stream * s, const auto & rhs) { (*s) << T{rhs}; return s; };
	return *std::accumulate(f, l, &stream, cast_and_shift);
}

} // namespace cthash::internal

#endif

#ifndef CTHASH_INTERNAL_DEDUCE_HPP
#define CTHASH_INTERNAL_DEDUCE_HPP

#include <concepts>
#include <cstdint>

namespace cthash::internal {

// support

template <typename T> concept digest_length_provided = requires() //
{
	{ static_cast<size_t>(T::digest_length) } -> std::same_as<size_t>;
};

template <typename T> concept digest_length_bit_provided = requires() //
{
	{ static_cast<size_t>(T::digest_length_bit) } -> std::same_as<size_t>;
};

template <typename T> concept initial_values_provided = requires() //
{
	{ static_cast<size_t>(T::initial_values.size() * sizeof(typename decltype(T::initial_values)::value_type)) } -> std::same_as<size_t>;
};

template <typename> static constexpr bool dependent_false = false;

template <typename Config> constexpr size_t digest_bytes_length_of = [] {
	if constexpr (digest_length_provided<Config>) {
		return static_cast<size_t>(Config::digest_length);
	} else if constexpr (digest_length_bit_provided<Config>) {
		return static_cast<size_t>(Config::digest_length_bit) / 8u;
	} else if constexpr (initial_values_provided<Config>) {
		return static_cast<size_t>(Config::initial_values.size() * sizeof(typename decltype(Config::initial_values)::value_type));
	} else {
		static_assert(dependent_false<Config>);
	}
}();

} // namespace cthash::internal

#endif
#ifndef CTHASH_INTERNAL_HEXDEC_HPP
#define CTHASH_INTERNAL_HEXDEC_HPP

#include <array>
#include <ostream>
#include <span>
#include <type_traits>

namespace cthash::internal {

consteval auto get_hexdec_table() noexcept {
	std::array<uint8_t, 128> result;

	auto char_to_hexdec = [](char c) {
		if (c >= '0' && c <= '9') {
			return static_cast<uint8_t>(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			return static_cast<uint8_t>(c - 'a' + 10);
		} else if (c >= 'A' && c <= 'F') {
			return static_cast<uint8_t>(c - 'A' + 10);
		} else {
			return static_cast<uint8_t>(0);
		}
	};

	for (int i = 0; i != static_cast<int>(result.size()); ++i) {
		result[static_cast<size_t>(i)] = char_to_hexdec(static_cast<char>(i));
	}

	return result;
}

constexpr auto hexdec_to_value_alphabet = get_hexdec_table();

template <typename CharT> constexpr auto value_to_hexdec_alphabet = std::array<CharT, 16>{CharT('0'), CharT('1'), CharT('2'), CharT('3'), CharT('4'), CharT('5'), CharT('6'), CharT('7'), CharT('8'), CharT('9'), CharT('a'), CharT('b'), CharT('c'), CharT('d'), CharT('e'), CharT('f')};

struct byte_hexdec_value {
	std::byte val;

	template <typename CharT, typename Traits> friend auto & operator<<(std::basic_ostream<CharT, Traits> & os, byte_hexdec_value rhs) {
		return os << value_to_hexdec_alphabet<CharT>[unsigned(rhs.val >> 4u)] << value_to_hexdec_alphabet<CharT>[unsigned(rhs.val) & 0b1111u];
	}
};

template <size_t N, typename CharT> constexpr auto hexdec_to_binary(std::span<const CharT, N * 2> in) -> std::array<std::byte, N> {
	return [in]<size_t... Idx>(std::index_sequence<Idx...>) {
		return std::array<std::byte, N>{static_cast<std::byte>(hexdec_to_value_alphabet[static_cast<size_t>(in[Idx * 2]) & 0b0111'1111u] << 4u | hexdec_to_value_alphabet[static_cast<size_t>(in[Idx * 2u + 1u]) & 0b0111'1111u])...};
	}
	(std::make_index_sequence<N>());
}

template <typename CharT, size_t N>
requires((N - 1) % 2 == 0) // -1 because of zero terminator in literals
constexpr auto literal_hexdec_to_binary(const CharT (&in)[N]) -> std::array<std::byte, (N - 1) / 2> {
	return hexdec_to_binary<N / 2>(std::span<const char, N - 1>(in, N - 1));
}

} // namespace cthash::internal

#endif

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

#ifndef CTHASH_INTERNAL_ASSERT_HPP
#define CTHASH_INTERNAL_ASSERT_HPP

#ifndef NDEBUG
#define CTHASH_ASSERT(e) cthash::assert_this(static_cast<bool>(e), #e, __FILE__, __LINE__);
#else
#define CTHASH_ASSERT(e) ((void)(0))
#endif

#include <cstdio>
#include <cstdlib>

namespace cthash {

constexpr void assert_this(bool value, const char * expression, const char * file, unsigned line) {
	if (!value) {
		printf("%s:%u: failed assertion '%s'\n", file, line, expression);
		std::abort();
	}
}

} // namespace cthash

#endif

#ifndef CTHASH_INTERNAL_BIT_HPP
#define CTHASH_INTERNAL_BIT_HPP

#include <bit>

namespace cthash::internal {

#if defined(__cpp_lib_byteswap) && __cpp_lib_byteswap >= 202110L

template <std::unsigned_integral T> [[gnu::always_inline]] constexpr auto byteswap(T val) noexcept {
	return std::byteswap(val);
}

#else

template <typename T, size_t N> concept unsigned_integral_of_size = (sizeof(T) == N) && std::unsigned_integral<T>;

template <unsigned_integral_of_size<1> T> constexpr auto byteswap(T val) noexcept {
	return val;
}

template <unsigned_integral_of_size<2> T> constexpr auto byteswap(T val) noexcept {
	return static_cast<T>(__builtin_bswap16(val));
}

template <unsigned_integral_of_size<4> T> constexpr auto byteswap(T val) noexcept {
	return static_cast<T>(__builtin_bswap32(val));
}

template <unsigned_integral_of_size<8> T> constexpr auto byteswap(T val) noexcept {
	return static_cast<T>(__builtin_bswap64(val));
}

#endif

} // namespace cthash::internal

#endif
#ifndef CTHASH_CONCEPTS_HPP
#define CTHASH_CONCEPTS_HPP

#include <span>

namespace cthash {

template <typename T> concept one_byte_char = (sizeof(T) == 1u);

template <typename T> concept byte_like = (sizeof(T) == 1u) && (std::same_as<T, char> || std::same_as<T, unsigned char> || std::same_as<T, char8_t> || std::same_as<T, std::byte> || std::same_as<T, uint8_t> || std::same_as<T, int8_t>);

template <one_byte_char CharT, size_t N> void string_literal_helper(const CharT (&)[N]);

template <typename T> concept string_literal = requires(const T & in) //
{
	string_literal_helper(in);
};

template <typename T> concept convertible_to_byte_span = requires(T && obj) //
{
	{ std::span(obj) };
	requires byte_like<typename decltype(std::span(obj))::value_type>;
	requires !string_literal<T>;
};

} // namespace cthash

#endif

#ifndef CTHASH_INTERNAL_CONVERT_HPP
#define CTHASH_INTERNAL_CONVERT_HPP

#include <span>
#include <type_traits>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace cthash {

template <typename It1, typename It2, typename It3> constexpr auto byte_copy(It1 first, It2 last, It3 destination) {
	return std::transform(first, last, destination, [](byte_like auto v) { return static_cast<std::byte>(v); });
}

template <std::unsigned_integral T, byte_like Byte> constexpr auto cast_from_bytes(std::span<const Byte, sizeof(T)> in) noexcept -> T {
	if consteval {
		return [&]<size_t... Idx>(std::index_sequence<Idx...>) -> T {
			return static_cast<T>(((static_cast<T>(in[Idx]) << ((sizeof(T) - 1u - Idx) * 8u)) | ...));
		}(std::make_index_sequence<sizeof(T)>());
	} else {
		T t;
		std::memcpy(&t, in.data(), sizeof(T));
		if constexpr (std::endian::native == std::endian::little) {
			return internal::byteswap(t);
		} else {
			return t;
		}
	}
}

template <std::unsigned_integral T, byte_like Byte> constexpr auto cast_from_le_bytes(std::span<const Byte, sizeof(T)> in) noexcept -> T {
	if consteval {
		return [&]<size_t... Idx>(std::index_sequence<Idx...>) -> T {
			return static_cast<T>(((static_cast<T>(in[Idx]) << static_cast<T>(Idx * 8u)) | ...));
		}(std::make_index_sequence<sizeof(T)>());
	} else {
		T t;
		std::memcpy(&t, in.data(), sizeof(T));
		if constexpr (std::endian::native == std::endian::big) {
			return internal::byteswap(t);
		} else {
			return t;
		}
	}
}

template <std::unsigned_integral T> struct unwrap_littleendian_number {
	static constexpr size_t bytes = sizeof(T);
	static constexpr size_t bits = bytes * 8u;

	std::span<std::byte, bytes> ref;

	constexpr void operator=(T value) noexcept {
		[&]<size_t... Idx>(std::index_sequence<Idx...>) {
			((ref[Idx] = static_cast<std::byte>(value >> (Idx * 8u))), ...);
		}(std::make_index_sequence<bytes>());
	}
};

unwrap_littleendian_number(std::span<std::byte, 8>) -> unwrap_littleendian_number<uint64_t>;
unwrap_littleendian_number(std::span<std::byte, 4>) -> unwrap_littleendian_number<uint32_t>;

template <std::unsigned_integral T> struct unwrap_bigendian_number {
	static constexpr size_t bytes = sizeof(T);
	static constexpr size_t bits = bytes * 8u;

	std::span<std::byte, bytes> ref;

	constexpr void operator=(T value) noexcept {
		[&]<size_t... Idx>(std::index_sequence<Idx...>) {
			((ref[Idx] = static_cast<std::byte>(value >> ((bits - 8u) - 8u * Idx))), ...);
		}(std::make_index_sequence<bytes>());
	}
};

unwrap_bigendian_number(std::span<std::byte, 8>) -> unwrap_bigendian_number<uint64_t>;
unwrap_bigendian_number(std::span<std::byte, 4>) -> unwrap_bigendian_number<uint32_t>;

} // namespace cthash

#endif

#include <algorithm>
#include <array>
#include <span>
#include <cassert>
#include <concepts>
#include <cstdint>

namespace cthash {

template <typename Config> struct internal_hasher {
	static constexpr auto config = Config{};
	static constexpr size_t block_size_bytes = config.block_bits / 8u;
	static constexpr size_t digest_bytes = internal::digest_bytes_length_of<Config>;

	// internal types
	using state_value_t = std::remove_cvref_t<decltype(Config::initial_values)>;
	using state_item_t = typename state_value_t::value_type;

	using block_value_t = std::array<std::byte, block_size_bytes>;
	using block_view_t = std::span<const std::byte, block_size_bytes>;

	using staging_item_t = typename decltype(config.constants)::value_type;
	static constexpr size_t staging_size = config.constants.size();
	using staging_value_t = std::array<staging_item_t, staging_size>;
	using staging_view_t = std::span<const staging_item_t, staging_size>;

	using digest_span_t = std::span<std::byte, digest_bytes>;
	using result_t = cthash::tagged_hash_value<Config>;
	using length_t = typename Config::length_type;

	// internal state
	state_value_t hash;
	length_t total_length;

	block_value_t block;
	unsigned block_used;

	// constructors
	constexpr internal_hasher() noexcept: hash{config.initial_values}, total_length{0u}, block_used{0u} { }
	constexpr internal_hasher(const internal_hasher &) noexcept = default;
	constexpr internal_hasher(internal_hasher &&) noexcept = default;
	constexpr ~internal_hasher() noexcept = default;

	// take buffer and build staging
	template <byte_like Byte> [[gnu::always_inline]] static constexpr auto build_staging(std::span<const Byte, block_size_bytes> chunk) noexcept -> staging_value_t {
		staging_value_t w;

		constexpr auto first_part_size = block_size_bytes / sizeof(staging_item_t);

		// fill first part with chunk
		for (int i = 0; i != int(first_part_size); ++i) {
			w[static_cast<size_t>(i)] = cast_from_bytes<staging_item_t>(chunk.subspan(static_cast<size_t>(i) * sizeof(staging_item_t)).template first<sizeof(staging_item_t)>());
		}

		// fill the rest (generify)
		for (int i = int(first_part_size); i != int(staging_size); ++i) {
			w[static_cast<size_t>(i)] = w[static_cast<size_t>(i - 16)] + config.sigma_0(w[static_cast<size_t>(i - 15)]) + w[static_cast<size_t>(i - 7)] + config.sigma_1(w[static_cast<size_t>(i - 2)]);
		}

		return w;
	}

	[[gnu::always_inline]] static constexpr auto build_staging(std::span<const std::byte, block_size_bytes> chunk) noexcept -> staging_value_t {
		return build_staging<std::byte>(chunk);
	}

	[[gnu::always_inline]] static constexpr void rounds(staging_view_t w, state_value_t & state) noexcept {
		config.rounds(w, state);
	}

	// this implementation works only with input size aligned to bytes (not bits)
	template <byte_like T> [[gnu::always_inline]] constexpr void update_to_buffer_and_process(std::span<const T> in) noexcept {
		// if block is not used, we can build staging directly
		if (block_used) {
			const auto remaining_free_space = std::span<std::byte, block_size_bytes>(block).subspan(block_used);
			const auto to_copy = in.first(std::min(in.size(), remaining_free_space.size()));

			const auto it = byte_copy(to_copy.begin(), to_copy.end(), remaining_free_space.begin());
			total_length += to_copy.size();

			// we didn't fill the block
			if (it != remaining_free_space.end()) {
				CTHASH_ASSERT(to_copy.size() == in.size());
				block_used += static_cast<unsigned>(to_copy.size());
				return;
			} else {
				block_used = 0u;
			}

			// we have block!
			const staging_value_t w = build_staging(block);
			rounds(w, hash);

			// remove part we processed
			in = in.subspan(to_copy.size());
		}

		// do the work over blocks without copy
		if (not block_used) {
			while (in.size() >= block_size_bytes) {
				const auto local_block = in.template first<block_size_bytes>();
				total_length += block_size_bytes;

				const staging_value_t w = build_staging<T>(local_block);
				rounds(w, hash);

				// remove part we processed
				in = in.subspan(block_size_bytes);
			}
		}

		// remainder is put onto temporary block
		if (not in.empty()) {
			CTHASH_ASSERT(block_used == 0u);
			CTHASH_ASSERT(in.size() < block_size_bytes);

			// copy it to block and let it stay there
			byte_copy(in.begin(), in.end(), block.begin());
			block_used = static_cast<unsigned>(in.size());
			total_length += block_used;
		}
	}

	[[gnu::always_inline]] static constexpr bool finalize_buffer(block_value_t & block, size_t block_used) noexcept {
		CTHASH_ASSERT(block_used < block.size());
		const auto free_space = std::span(block).subspan(block_used);

		auto it = free_space.data();
		*it++ = std::byte{0b1000'0000u};							   // first byte after data contains bit at MSB
		std::fill(it, (block.data() + block.size()), std::byte{0x0u}); // rest is filled with zeros

		// we don't have enough space to write length bits
		return free_space.size() < (1u + (config.length_size_bits / 8u));
	}

	[[gnu::always_inline]] static constexpr void finalize_buffer_by_writing_length(block_value_t & block, length_t total_length) noexcept {
		unwrap_bigendian_number{std::span(block).template last<sizeof(length_t)>()} = (total_length * 8u);
	}

	[[gnu::always_inline]] constexpr void finalize() noexcept {
		if (finalize_buffer(block, block_used)) {
			// we didn't have enough space, we need to process block
			const staging_value_t w = build_staging(block);
			rounds(w, hash);

			// zero it out
			std::fill(block.begin(), block.end(), std::byte{0x0u});
		}

		// we either have space to write or we have zerod out block
		finalize_buffer_by_writing_length(block, total_length);

		// calculate last round
		const staging_value_t w = build_staging(block);
		rounds(w, hash);
	}

	[[gnu::always_inline]] constexpr void write_result_into(digest_span_t out) noexcept
	requires(digest_bytes % sizeof(state_item_t) == 0u)
	{
		// copy result to byte result
		constexpr size_t values_for_output = digest_bytes / sizeof(state_item_t);
		static_assert(values_for_output <= config.initial_values.size());

		for (int i = 0; i != values_for_output; ++i) {
			unwrap_bigendian_number<state_item_t>{out.subspan(static_cast<size_t>(i) * sizeof(state_item_t)).template first<sizeof(state_item_t)>()} = hash[static_cast<size_t>(i)];
		}
	}

	[[gnu::always_inline]] constexpr void write_result_into(digest_span_t out) noexcept
	requires(digest_bytes % sizeof(state_item_t) != 0u)
	{
		// this is only used when digest doesn't align with output buffer

		// make sure digest size is smaller than hash state
		static_assert(digest_bytes <= config.initial_values.size() * sizeof(state_item_t));

		// copy result to byte result
		std::array<std::byte, sizeof(state_item_t) * config.initial_values.size()> tmp_buffer;

		for (int i = 0; i != (int)config.initial_values.size(); ++i) {
			unwrap_bigendian_number<state_item_t>{std::span(tmp_buffer).subspan(static_cast<size_t>(i) * sizeof(state_item_t)).template first<sizeof(state_item_t)>()} = hash[static_cast<size_t>(i)];
		}

		std::copy_n(tmp_buffer.data(), digest_bytes, out.data());
	}
};

// this is a convinience type for nicer UX...
template <typename Config> struct hasher: private internal_hasher<Config> {
	using super = internal_hasher<Config>;
	using result_t = typename super::result_t;
	using length_t = typename super::length_t;
	using digest_span_t = typename super::digest_span_t;

	constexpr hasher() noexcept: super() { }
	constexpr hasher(const hasher &) noexcept = default;
	constexpr hasher(hasher &&) noexcept = default;
	constexpr ~hasher() noexcept = default;

	// support for various input types
	constexpr hasher & update(std::span<const std::byte> input) noexcept {
		super::update_to_buffer_and_process(input);
		return *this;
	}

	template <convertible_to_byte_span T> constexpr hasher & update(const T & something) noexcept {
		using value_type = typename decltype(std::span(something))::value_type;
		super::update_to_buffer_and_process(std::span<const value_type>(something));
		return *this;
	}

	template <one_byte_char CharT> constexpr hasher & update(std::basic_string_view<CharT> in) noexcept {
		super::update_to_buffer_and_process(std::span(in.data(), in.size()));
		return *this;
	}

	template <string_literal T> constexpr hasher & update(const T & lit) noexcept {
		super::update_to_buffer_and_process(std::span(lit, std::size(lit) - 1u));
		return *this;
	}

	// output (by reference or by value)
	constexpr void final(digest_span_t digest) noexcept {
		super::finalize();
		super::write_result_into(digest);
	}

	constexpr auto final() noexcept {
		result_t output;
		this->final(output);
		return output;
	}

	constexpr length_t size() const noexcept {
		return super::total_length;
	}
};

} // namespace cthash

#endif

#include <array>
#include <span>
#include <concepts>
#include <cstdint>

namespace cthash::sha2 {

template <std::unsigned_integral T> [[gnu::always_inline]] constexpr auto choice(T e, T f, T g) noexcept -> T {
	return (e bitand f) xor (~e bitand g);
}

template <std::unsigned_integral T> [[gnu::always_inline]] constexpr auto majority(T a, T b, T c) noexcept -> T {
	return (a bitand b) xor (a bitand c) xor (b bitand c);
}

template <typename Config, typename StageT, size_t StageLength, typename StateT, size_t StateLength>
[[gnu::always_inline]] constexpr void rounds(std::span<const StageT, StageLength> w, std::array<StateT, StateLength> & state) noexcept {
	using state_t = std::array<StateT, StateLength>;

	// create copy of internal state
	auto wvar = state_t(state);

	// just give them names
	auto & [a, b, c, d, e, f, g, h] = wvar;

	// number of rounds is same as constants
	static_assert(StageLength == Config::constants.size());

	for (int i = 0; i != Config::constants.size(); ++i) {
		const auto temp1 = h + Config::sum_e(e) + choice(e, f, g) + Config::constants[static_cast<size_t>(i)] + w[static_cast<size_t>(i)];
		const auto temp2 = Config::sum_a(a) + majority(a, b, c);

		// move around (that's rotate)
		std::rotate(wvar.begin(), wvar.begin() + 7u, wvar.end());

		e += temp1;
		a = temp1 + temp2;

		// originally it was:
		// h = g;
		// g = f;
		// f = e;
		// e = d + temp1;
		// d = c;
		// c = b;
		// b = a;
		// a = temp1 + temp2;
	}

	// add store back
	for (int i = 0; i != (int)state.size(); ++i) {
		state[static_cast<size_t>(i)] += wvar[static_cast<size_t>(i)];
	}
}

} // namespace cthash::sha2

#endif

namespace cthash {

struct sha256_config {
	using length_type = uint64_t;
	static constexpr size_t length_size_bits = 64;

	static constexpr size_t block_bits = 512u;

	static constexpr auto initial_values = std::array<uint32_t, 8>{0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul};

	// staging sigmas
	[[gnu::always_inline]] static constexpr auto sigma_0(uint32_t w_15) noexcept -> uint32_t {
		return std::rotr(w_15, 7u) xor std::rotr(w_15, 18u) xor (w_15 >> 3u);
	}

	[[gnu::always_inline]] static constexpr auto sigma_1(uint32_t w_2) noexcept -> uint32_t {
		return std::rotr(w_2, 17u) xor std::rotr(w_2, 19u) xor (w_2 >> 10u);
	}

	// rounds constants...
	static constexpr auto constants = std::array<uint32_t, 64>{
		0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
		0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
		0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul, 0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
		0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
		0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
		0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
		0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
		0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul, 0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul};

	// rounds sums
	[[gnu::always_inline]] static constexpr auto sum_a(uint32_t a) noexcept -> uint32_t {
		return std::rotr(a, 2u) xor std::rotr(a, 13u) xor std::rotr(a, 22u);
	}

	[[gnu::always_inline]] static constexpr auto sum_e(uint32_t e) noexcept -> uint32_t {
		return std::rotr(e, 6u) xor std::rotr(e, 11u) xor std::rotr(e, 25u);
	}

	// rounds
	[[gnu::always_inline]] static constexpr void rounds(std::span<const uint32_t, 64> w, std::array<uint32_t, 8> & state) noexcept {
		return sha2::rounds<sha256_config>(w, state);
	}
};

static_assert(not cthash::internal::digest_length_provided<sha256_config>);
static_assert(cthash::internal::digest_bytes_length_of<sha256_config> == 32u);

using sha256 = hasher<sha256_config>;
using sha256_value = tagged_hash_value<sha256_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha256() {
		return sha256_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

namespace cthash {

struct sha224_config: sha256_config {
	// these are only changes against sha256 specification...

	static constexpr size_t digest_length = 28u;

	static constexpr auto initial_values = std::array<uint32_t, 8>{0xc1059ed8ul, 0x367cd507ul, 0x3070dd17ul, 0xf70e5939ul, 0xffc00b31ul, 0x68581511ul, 0x64f98fa7ul, 0xbefa4fa4ul};
};

static_assert(cthash::internal::digest_length_provided<sha224_config>);
static_assert(cthash::internal::digest_bytes_length_of<sha224_config> == 28u);

using sha224 = hasher<sha224_config>;
using sha224_value = tagged_hash_value<sha224_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha224() {
		return sha224_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA2_SHA384_HPP
#define CTHASH_SHA2_SHA384_HPP

#ifndef CTHASH_SHA2_SHA512_HPP
#define CTHASH_SHA2_SHA512_HPP

namespace cthash {

struct sha512_config {
	using length_type = uint64_t;
	static constexpr size_t length_size_bits = 128;

	static constexpr size_t block_bits = 1024u;

	static constexpr auto initial_values = std::array<uint64_t, 8>{0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};

	// staging functions
	[[gnu::always_inline]] static constexpr auto sigma_0(uint64_t w_15) noexcept -> uint64_t {
		return std::rotr(w_15, 1u) xor std::rotr(w_15, 8u) xor (w_15 >> 7u);
	}

	[[gnu::always_inline]] static constexpr auto sigma_1(uint64_t w_2) noexcept -> uint64_t {
		return std::rotr(w_2, 19u) xor std::rotr(w_2, 61u) xor (w_2 >> 6u);
	}

	// rounds constants...
	static constexpr auto constants = std::array<uint64_t, 80>{
		0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull,
		0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull,
		0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
		0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
		0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 0x983e5152ee66dfabull,
		0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
		0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull,
		0x53380d139d95b3dfull, 0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
		0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
		0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
		0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull,
		0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
		0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull,
		0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
		0x113f9804bef90daeull, 0x1b710b35131c471bull, 0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
		0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

	[[gnu::always_inline]] static constexpr auto sum_a(uint64_t a) noexcept -> uint64_t {
		return std::rotr(a, 28u) xor std::rotr(a, 34u) xor std::rotr(a, 39u);
	}

	[[gnu::always_inline]] static constexpr auto sum_e(uint64_t e) noexcept -> uint64_t {
		return std::rotr(e, 14u) xor std::rotr(e, 18u) xor std::rotr(e, 41u);
	}

	// rounds
	[[gnu::always_inline]] static constexpr void rounds(std::span<const uint64_t, 80> w, std::array<uint64_t, 8> & state) noexcept {
		return sha2::rounds<sha512_config>(w, state);
	}
};

static_assert(not cthash::internal::digest_length_provided<sha512_config>);
static_assert(cthash::internal::digest_bytes_length_of<sha512_config> == 64u);

using sha512 = hasher<sha512_config>;
using sha512_value = tagged_hash_value<sha512_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha512() {
		return sha512_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

namespace cthash {

struct sha384_config: sha512_config {
	static constexpr size_t digest_length = 48u;

	static constexpr auto initial_values = std::array<uint64_t, 8>{0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull, 0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull};
};

static_assert(cthash::internal::digest_length_provided<sha384_config>);
static_assert(cthash::internal::digest_bytes_length_of<sha384_config> == 48u);

using sha384 = hasher<sha384_config>;
using sha384_value = tagged_hash_value<sha384_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha384() {
		return sha384_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA2_SHA512_T_HPP
#define CTHASH_SHA2_SHA512_T_HPP

namespace cthash {

namespace sha256t_support {

	static consteval size_t width_of_decimal(unsigned t) {
		if (t < 10u) {
			return 1u;
		} else if (t < 100u) {
			return 2u;
		} else if (t < 1000u) {
			return 3u;
		} else {
			throw "we don't support more than three digits!";
		}
	}

	template <unsigned Width> static consteval auto generate_signature(unsigned t) {
		const char a = '0' + static_cast<char>((t / 100u) % 10u);
		const char b = '0' + static_cast<char>((t / 10u) % 10u);
		const char c = '0' + static_cast<char>((t / 1u) % 10u);

		if constexpr (Width == 1) {
			return std::array<char, Width + 8u>{'S', 'H', 'A', '-', '5', '1', '2', '/', c};
		} else if constexpr (Width == 2) {
			return std::array<char, Width + 8u>{'S', 'H', 'A', '-', '5', '1', '2', '/', b, c};
		} else if constexpr (Width == 3) {
			return std::array<char, Width + 8u>{'S', 'H', 'A', '-', '5', '1', '2', '/', a, b, c};
		} else {
			throw "we don't support greater width than 3";
		}
	}

} // namespace sha256t_support

static consteval auto calculate_sha512t_iv(std::span<const char> in) {
	auto sha512hasher = internal_hasher<sha512_config>{};

	// modify IV
	for (auto & val: sha512hasher.hash) {
		val = val xor 0xa5a5a5a5a5a5a5a5ull;
	}

	sha512hasher.update_to_buffer_and_process(in);
	sha512hasher.finalize();
	return sha512hasher.hash;
}

template <size_t T> constexpr auto signature_for_sha512t = sha256t_support::generate_signature<sha256t_support::width_of_decimal(T)>(T);
template <size_t T> constexpr auto iv_for_sha512t = calculate_sha512t_iv(signature_for_sha512t<T>);

template <unsigned T> struct sha512t_config: sha512_config {
	static_assert(T % 8u == 0u, "only hashes aligned to bytes are supported");
	static_assert(T != 384u, "sha-512/384 is not allowed, use sha-384 instead");
	static_assert(T <= 512u, "T can't be larger than 512");
	static_assert(T != 0u, "T can't be zero");

	static constexpr size_t digest_length = T / 8u;

	static constexpr std::array<uint64_t, 8> initial_values = iv_for_sha512t<T>;
};

static_assert(cthash::internal::digest_length_provided<sha512t_config<224>>);
static_assert(cthash::internal::digest_length_provided<sha512t_config<256>>);
static_assert(cthash::internal::digest_bytes_length_of<sha512t_config<224>> == 28u);
static_assert(cthash::internal::digest_bytes_length_of<sha512t_config<256>> == 32u);

template <unsigned T> using sha512t = hasher<sha512t_config<T>>;
template <unsigned T> using sha512t_value = tagged_hash_value<sha512t_config<T>>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha512_224() {
		return sha512t_value<224>(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_sha512_256() {
		return sha512t_value<256>(Value);
	}

} // namespace literals

} // namespace cthash

#endif

// SHA-3 (keccak) family
#ifndef CTHASH_SHA3_SHA3_224_HPP
#define CTHASH_SHA3_SHA3_224_HPP

#ifndef CTHASH_SHA3_COMMON_HPP
#define CTHASH_SHA3_COMMON_HPP

#ifndef CTHASH_SHA3_KECCAK_HPP
#define CTHASH_SHA3_KECCAK_HPP

#include <array>
#include <bit>
#include <span>
#include <type_traits>
#include <utility>
#include <concepts>
#include <cstdint>

namespace cthash::keccak {

// inspired by tiny-keccak (https://github.com/debris/tiny-keccak from Marek Kotewicz)

static constexpr auto rho = std::array<uint8_t, 24>{1u, 3u, 6u, 10u, 15u, 21u, 28u, 36u, 45u, 55u, 2u, 14u, 27u, 41u, 56u, 8u, 25u, 43u, 62u, 18u, 39u, 61u, 20u, 44u};

static constexpr auto pi = std::array<uint8_t, 24>{10u, 7u, 11u, 17u, 18u, 3u, 5u, 16u, 8u, 21u, 24u, 4u, 15u, 23u, 19u, 13u, 12u, 2u, 20u, 14u, 22u, 9u, 6u, 1u};

static constexpr auto rc = std::array<uint64_t, 24>{0x1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL, 0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

struct state_1600: std::array<uint64_t, (5u * 5u)> { };

struct state_1600_ref: std::span<uint64_t, (5u * 5u)> {
	using super = std::span<uint64_t, (5u * 5u)>;
	using super::super;
};

[[gnu::always_inline, gnu::flatten]] constexpr void theta(state_1600_ref state) noexcept {
	// xor of columns
	const auto b = std::array<uint64_t, 5>{
		state[0] xor state[5] xor state[10] xor state[15] xor state[20],
		state[1] xor state[6] xor state[11] xor state[16] xor state[21],
		state[2] xor state[7] xor state[12] xor state[17] xor state[22],
		state[3] xor state[8] xor state[13] xor state[18] xor state[23],
		state[4] xor state[9] xor state[14] xor state[19] xor state[24],
	};

	const auto tmp = std::array<uint64_t, 5>{
		b[4] xor std::rotl(b[1], 1),
		b[0] xor std::rotl(b[2], 1),
		b[1] xor std::rotl(b[3], 1),
		b[2] xor std::rotl(b[4], 1),
		b[3] xor std::rotl(b[0], 1),
	};

	[&]<size_t... Idx>(std::index_sequence<Idx...>) {
		((state[Idx] ^= tmp[Idx % 5u]), ...);
	}(std::make_index_sequence<25>());
}

[[gnu::always_inline, gnu::flatten]] constexpr void rho_pi(state_1600_ref state) noexcept {
	uint64_t tmp = state[1];

	[&]<size_t... Idx>(std::index_sequence<Idx...>) {
		((state[pi[Idx]] = std::rotl(std::exchange(tmp, state[pi[Idx]]), rho[Idx])), ...);
	}(std::make_index_sequence<24>());
}

[[gnu::always_inline, gnu::flatten]] constexpr void chi(state_1600_ref state) noexcept {
	constexpr auto chi_helper = [](std::span<uint64_t, 5> row) {
		const auto b = std::array<uint64_t, 5>{row[0], row[1], row[2], row[3], row[4]};

		row[0] = b[0] xor ((~b[1]) bitand b[2]);
		row[1] = b[1] xor ((~b[2]) bitand b[3]);
		row[2] = b[2] xor ((~b[3]) bitand b[4]);
		row[3] = b[3] xor ((~b[4]) bitand b[0]);
		row[4] = b[4] xor ((~b[0]) bitand b[1]);
	};

	chi_helper(state.subspan<0>().first<5>());
	chi_helper(state.subspan<5>().first<5>());
	chi_helper(state.subspan<10>().first<5>());
	chi_helper(state.subspan<15>().first<5>());
	chi_helper(state.subspan<20>().first<5>());
}

[[gnu::flatten]] constexpr void keccak_f(state_1600 & state) noexcept {
	// rounds
	for (int i = 0; i != 24; ++i) {
		// theta (xor each column together)
		theta(state);
		rho_pi(state);
		chi(state);
		state[0] ^= rc[static_cast<size_t>(i)];
	}
}

} // namespace cthash::keccak

#endif

#include <cstdint>

namespace cthash {

template <typename T, typename Y> concept castable_to = requires(T val) { {static_cast<Y>(val)} -> std::same_as<Y>; };

template <size_t N> struct keccak_suffix {
	unsigned bits;
	std::array<std::byte, N> values;

	constexpr keccak_suffix(unsigned b, castable_to<std::byte> auto... v) noexcept: bits{b}, values{static_cast<std::byte>(v)...} { }
};

template <castable_to<std::byte>... Ts> keccak_suffix(unsigned, Ts...) -> keccak_suffix<sizeof...(Ts)>;

template <typename T> struct identify;

template <typename T, byte_like Byte> constexpr auto convert_prefix_into_aligned(std::span<const Byte> input, unsigned pos) noexcept -> std::array<std::byte, sizeof(T)> {
	CTHASH_ASSERT(input.size() <= sizeof(T));
	CTHASH_ASSERT(pos <= sizeof(T));
	CTHASH_ASSERT((input.size() + pos) <= sizeof(T));

	std::array<std::byte, sizeof(T)> buffer{};

	std::fill(buffer.begin(), buffer.end(), std::byte{0});
	std::transform(input.data(), input.data() + input.size(), buffer.data() + pos, [](auto v) { return static_cast<std::byte>(v); });

	return buffer;
}

template <typename T, byte_like Byte> constexpr auto convert_prefix_into_value(std::span<const Byte> input, unsigned pos) noexcept -> uint64_t {
	const auto tmp = convert_prefix_into_aligned<T, Byte>(input, pos);
	return cast_from_le_bytes<T>(std::span<const std::byte, 8>(tmp));
}

template <typename Config> struct basic_keccak_hasher {
	static_assert(Config::digest_length_bit % 8u == 0u);
	static_assert(Config::rate_bit % 8u == 0u);
	static_assert(Config::capacity_bit % 8u == 0u);

	static_assert((Config::rate_bit + Config::capacity_bit) == 1600u, "Only Keccak 1600 is implemented");

	static constexpr size_t digest_length = Config::digest_length_bit / 8u;
	static constexpr size_t rate = Config::rate_bit / 8u;
	static constexpr size_t capacity = Config::capacity_bit / 8u;

	using result_t = cthash::tagged_hash_value<Config>;
	using digest_span_t = std::span<std::byte, digest_length>;

	keccak::state_1600 internal_state{};
	uint8_t position{0u};

	constexpr basic_keccak_hasher() noexcept {
		std::fill(internal_state.begin(), internal_state.end(), uint64_t{0});
	}

	template <byte_like T> constexpr size_t xor_overwrite_block(std::span<const T> input) noexcept {
		using value_t = keccak::state_1600::value_type;

		if ((std::is_constant_evaluated() | (std::endian::native != std::endian::little))) {
			CTHASH_ASSERT((size_t(position) + input.size()) <= rate);

			// unaligned prefix (by copying from left to right it should be little endian)
			if (position % sizeof(value_t) != 0u) {
				// xor unaligned value and move to aligned if possible
				const size_t prefix_size = std::min(input.size(), sizeof(value_t) - (position % sizeof(value_t)));
				internal_state[position / sizeof(uint64_t)] ^= convert_prefix_into_value<value_t>(input.first(prefix_size), static_cast<unsigned>(position % sizeof(value_t)));
				position += static_cast<uint8_t>(prefix_size);
				input = input.subspan(prefix_size);
			}

			// aligned blocks
			while (input.size() >= sizeof(value_t)) {
				// xor aligned value and move to next
				internal_state[position / sizeof(value_t)] ^= cast_from_le_bytes<value_t>(input.template first<sizeof(value_t)>());
				position += static_cast<uint8_t>(sizeof(value_t));
				input = input.subspan(sizeof(value_t));
			}

			// unaligned suffix
			if (not input.empty()) {
				// xor and finish
				internal_state[position / sizeof(value_t)] ^= convert_prefix_into_value<value_t>(input, 0u);
				position += static_cast<uint8_t>(input.size());
			}

			return position;
		} else {
			const auto buffer = std::as_writable_bytes(std::span<uint64_t>(internal_state));
			const auto remaining = buffer.subspan(position);
			const auto place = remaining.first(std::min(input.size(), remaining.size()));

			std::transform(place.data(), place.data() + place.size(), input.data(), place.data(), [](std::byte lhs, auto rhs) { return lhs ^ static_cast<std::byte>(rhs); });

			position += static_cast<uint8_t>(place.size());
			return position;
		}
	}

	template <byte_like T> constexpr auto update(std::span<const T> input) noexcept {
		CTHASH_ASSERT(position < rate);
		const size_t remaining_in_buffer = rate - position;

		if (remaining_in_buffer > input.size()) {
			// xor overwrite as much as we can, and that's all
			xor_overwrite_block(input);
			CTHASH_ASSERT(position < rate);
			return;
		}

		// finish block and call keccak :)
		const auto first_part = input.first(remaining_in_buffer);
		input = input.subspan(remaining_in_buffer);
		xor_overwrite_block(first_part);
		CTHASH_ASSERT(position == rate);
		keccak_f(internal_state);
		position = 0u;

		// for each full block we can absorb directly
		while (input.size() >= rate) {
			const auto block = input.template first<rate>();
			input = input.subspan(rate);
			CTHASH_ASSERT(position == 0u);
			xor_overwrite_block<T>(block);
			keccak_f(internal_state);
			position = 0u;
		}

		// xor overwrite internal state with current remainder, and set position to end of it
		if (not input.empty()) {
			CTHASH_ASSERT(position == 0u);
			xor_overwrite_block(input);
			CTHASH_ASSERT(position < rate);
		}
	}

	// pad the message
	constexpr void xor_padding_block() noexcept {
		CTHASH_ASSERT(position < rate);

		constexpr const auto & suffix = Config::suffix;
		constexpr std::byte suffix_and_start_of_padding = (suffix.values[0] | (std::byte{0b0000'0001u} << suffix.bits));

		internal_state[position / sizeof(uint64_t)] ^= uint64_t(suffix_and_start_of_padding) << ((position % sizeof(uint64_t)) * 8u);
		internal_state[(rate - 1u) / sizeof(uint64_t)] ^= 0x8000000000000000ull; // last bit
	}

	constexpr void final_absorb() noexcept {
		xor_padding_block();
		keccak_f(internal_state);
	}

	// get resulting hash
	constexpr void squeeze(std::span<std::byte> output) noexcept {
		using value_t = keccak::state_1600::value_type;

		static_assert((rate % sizeof(value_t)) == 0u);
		auto r = std::span<const value_t>(internal_state).first(rate / sizeof(value_t));

		// aligned results will be processed here...
		while ((output.size() >= sizeof(value_t))) {
			// if we ran out of `rate` part, we need to squeeze another block
			if (r.empty()) {
				keccak_f(internal_state);
				r = std::span<const value_t>(internal_state).first(rate / sizeof(value_t));
			}

			// look at current to process
			const value_t current = r.front();
			const auto part = output.first<sizeof(value_t)>();

			// convert
			unwrap_littleendian_number<value_t>{part} = current;

			// move to next
			r = r.subspan(1u);
			output = output.subspan(sizeof(value_t));
		}

		// unaligned result is here
		if (!output.empty()) {
			// if we ran out of `rate` part, we need to squeeze another block
			if (r.empty()) {
				keccak_f(internal_state);
				r = std::span<const value_t>(internal_state).first(rate / sizeof(value_t));
			}

			const value_t current = r.front();

			// convert
			std::array<std::byte, sizeof(value_t)> tmp;
			unwrap_littleendian_number<value_t>{tmp} = current;
			CTHASH_ASSERT(tmp.size() > output.size());
			std::copy_n(tmp.data(), output.size(), output.data());
		}
	}

	constexpr void squeeze(digest_span_t output_fixed) noexcept
		requires((digest_length < rate) && digest_length != 0u)
	{
		auto output = std::span<std::byte>(output_fixed);

		// we don't need to squeeze anything
		using value_t = keccak::state_1600::value_type;

		static_assert((rate % sizeof(value_t)) == 0u);
		auto r = std::span<const value_t>(internal_state).first(rate / sizeof(value_t));

		// aligned results will be processed here...
		while ((output.size() >= sizeof(value_t))) {
			CTHASH_ASSERT(!r.empty());
			// look at current to process
			const value_t current = r.front();
			const auto part = output.template first<sizeof(value_t)>();

			// convert
			unwrap_littleendian_number<value_t>{part} = current;

			// move to next
			r = r.subspan(1u);
			output = output.subspan(sizeof(value_t));
		}

		if constexpr ((output_fixed.size() % sizeof(value_t)) != 0u) {
			// unaligned result is here
			CTHASH_ASSERT(!output.empty());
			CTHASH_ASSERT(!r.empty());

			const value_t current = r.front();

			// convert
			std::array<std::byte, sizeof(value_t)> tmp;
			unwrap_littleendian_number<value_t>{tmp} = current;
			CTHASH_ASSERT(tmp.size() > output.size());
			std::copy_n(tmp.data(), output.size(), output.data());
		}
	}

	constexpr void final(digest_span_t digest) noexcept
		requires(digest_length != 0u)
	{
		final_absorb();
		squeeze(digest);
	}

	constexpr result_t final() noexcept
		requires(digest_length != 0u)
	{
		result_t output;
		final(output);
		return output;
	}

	template <size_t N> constexpr auto final() noexcept
		requires(digest_length == 0u)
	{
		static_assert(N % 8u == 0u, "Only whole bytes are supported!");
		using result_type = typename Config::template variable_digest<N>;
		result_type output;
		final_absorb();
		squeeze(output);
		return output;
	}
};

template <typename Config> struct keccak_hasher: basic_keccak_hasher<Config> {
	using super = basic_keccak_hasher<Config>;
	using result_t = typename super::result_t;
	using digest_span_t = typename super::digest_span_t;

	constexpr keccak_hasher() noexcept: super() { }
	constexpr keccak_hasher(const keccak_hasher &) noexcept = default;
	constexpr keccak_hasher(keccak_hasher &&) noexcept = default;
	constexpr ~keccak_hasher() noexcept = default;

	constexpr keccak_hasher & update(std::span<const std::byte> input) noexcept {
		super::update(input);
		return *this;
	}

	template <convertible_to_byte_span T> constexpr keccak_hasher & update(const T & something) noexcept {
		using value_type = typename decltype(std::span(something))::value_type;
		super::update(std::span<const value_type>(something));
		return *this;
	}

	template <one_byte_char CharT> constexpr keccak_hasher & update(std::basic_string_view<CharT> in) noexcept {
		super::update(std::span(in.data(), in.size()));
		return *this;
	}

	template <string_literal T> constexpr keccak_hasher & update(const T & lit) noexcept {
		super::update(std::span(lit, std::size(lit) - 1u));
		return *this;
	}

	using super::final;
};

} // namespace cthash

#endif

namespace cthash {

struct sha3_224_config {
	static constexpr size_t digest_length_bit = 224u;
	static constexpr size_t capacity_bit = digest_length_bit * 2u;
	static constexpr size_t rate_bit = 1600u - capacity_bit;

	static constexpr auto suffix = keccak_suffix(2, 0b0000'0010u); // in reverse
};

static_assert((sha3_224_config::capacity_bit + sha3_224_config::rate_bit) == 1600u);

using sha3_224 = cthash::keccak_hasher<sha3_224_config>;
using sha3_224_value = tagged_hash_value<sha3_224_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_224() {
		return sha3_224_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA3_SHA3_256_HPP
#define CTHASH_SHA3_SHA3_256_HPP

namespace cthash {

struct sha3_256_config {
	static constexpr size_t digest_length_bit = 256u;
	static constexpr size_t capacity_bit = digest_length_bit * 2u;
	static constexpr size_t rate_bit = 1600u - capacity_bit;

	static constexpr auto suffix = keccak_suffix(2, 0b0000'0010u); // in reverse
};

static_assert((sha3_256_config::capacity_bit + sha3_256_config::rate_bit) == 1600u);

using sha3_256 = cthash::keccak_hasher<sha3_256_config>;
using sha3_256_value = tagged_hash_value<sha3_256_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_256() {
		return sha3_256_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA3_SHA3_384_HPP
#define CTHASH_SHA3_SHA3_384_HPP

namespace cthash {

struct sha3_384_config {
	static constexpr size_t digest_length_bit = 384u;
	static constexpr size_t capacity_bit = digest_length_bit * 2u;
	static constexpr size_t rate_bit = 1600u - capacity_bit;

	static constexpr auto suffix = keccak_suffix(2, 0b0000'0010u); // in reverse
};

static_assert((sha3_384_config::capacity_bit + sha3_384_config::rate_bit) == 1600u);

using sha3_384 = cthash::keccak_hasher<sha3_384_config>;
using sha3_384_value = tagged_hash_value<sha3_384_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_384() {
		return sha3_384_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA3_SHA3_512_HPP
#define CTHASH_SHA3_SHA3_512_HPP

namespace cthash {

struct sha3_512_config {
	static constexpr size_t digest_length_bit = 512u;
	static constexpr size_t capacity_bit = digest_length_bit * 2u;
	static constexpr size_t rate_bit = 1600u - capacity_bit;

	static constexpr auto suffix = keccak_suffix(2, 0b0000'0010u); // in reverse
};

static_assert((sha3_512_config::capacity_bit + sha3_512_config::rate_bit) == 1600u);

using sha3_512 = cthash::keccak_hasher<sha3_512_config>;
using sha3_512_value = tagged_hash_value<sha3_512_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_512() {
		return sha3_512_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA3_SHAKE128_HPP
#define CTHASH_SHA3_SHAKE128_HPP

namespace cthash {

template <size_t N> struct shake128_value;

struct shake128_config {
	template <size_t N> using variable_digest = shake128_value<N>;

	static constexpr size_t digest_length_bit = 0;

	static constexpr size_t capacity_bit = 256;
	static constexpr size_t rate_bit = 1344;

	static constexpr auto suffix = keccak_suffix(4, 0b0000'1111u); // in reverse
};

static_assert((shake128_config::capacity_bit + shake128_config::rate_bit) == 1600u);

using shake128 = cthash::keccak_hasher<shake128_config>;

template <size_t N> struct shake128_value: tagged_hash_value<variable_bit_length_tag<N, shake128_config>> {
	static_assert(N > 0);
	using super = tagged_hash_value<variable_bit_length_tag<N, shake128_config>>;
	using super::super;

	template <typename CharT> explicit constexpr shake128_value(const fixed_string<CharT, N / 8u> & in) noexcept: super{in} { }

	template <size_t K> constexpr friend bool operator==(const shake128_value & lhs, const shake128_value<K> & rhs) noexcept {
		static_assert(K > 0);
		constexpr auto smallest_n = std::min(N, K);
		const auto lhs_view = std::span<const std::byte, smallest_n / 8u>(lhs.data(), smallest_n / 8u);
		const auto rhs_view = std::span<const std::byte, smallest_n / 8u>(rhs.data(), smallest_n / 8u);
		return std::equal(lhs_view.begin(), lhs_view.end(), rhs_view.begin());
	}

	template <size_t K> constexpr friend auto operator<=>(const shake128_value & lhs, const shake128_value<K> & rhs) noexcept {
		static_assert(K > 0);
		constexpr auto smallest_n = std::min(N, K);
		return internal::threeway_compare_of_same_size(lhs.data(), rhs.data(), smallest_n / 8u);
	}
};

template <typename CharT, size_t N>
requires(N % 2 == 0)
shake128_value(const fixed_string<CharT, N> &) -> shake128_value<N * 4u>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_shake128() {
		return shake128_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#ifndef CTHASH_SHA3_SHAKE256_HPP
#define CTHASH_SHA3_SHAKE256_HPP

namespace cthash {

template <size_t N> struct shake256_value;

struct shake256_config {
	template <size_t N> using variable_digest = shake256_value<N>;

	static constexpr size_t digest_length_bit = 0;

	static constexpr size_t capacity_bit = 512;
	static constexpr size_t rate_bit = 1088;

	static constexpr auto suffix = keccak_suffix(4, 0b0000'1111u); // in reverse
};

static_assert((shake256_config::capacity_bit + shake256_config::rate_bit) == 1600u);

using shake256 = cthash::keccak_hasher<shake256_config>;

template <size_t N> struct shake256_value: tagged_hash_value<variable_bit_length_tag<N, shake256_config>> {
	static_assert(N > 0);
	using super = tagged_hash_value<variable_bit_length_tag<N, shake256_config>>;
	using super::super;

	template <typename CharT> explicit constexpr shake256_value(const fixed_string<CharT, N / 8u> & in) noexcept: super{in} { }

	template <size_t K> constexpr friend bool operator==(const shake256_value & lhs, const shake256_value<K> & rhs) noexcept {
		constexpr auto smallest_n = std::min(N, K);
		const auto lhs_view = std::span<const std::byte, smallest_n / 8u>(lhs.data(), smallest_n / 8u);
		const auto rhs_view = std::span<const std::byte, smallest_n / 8u>(rhs.data(), smallest_n / 8u);
		return std::equal(lhs_view.begin(), lhs_view.end(), rhs_view.begin());
	}

	template <size_t K> constexpr friend auto operator<=>(const shake256_value & lhs, const shake256_value<K> & rhs) noexcept {
		constexpr auto smallest_n = std::min(N, K);
		return internal::threeway_compare_of_same_size(lhs.data(), rhs.data(), smallest_n / 8u);
	}
};

template <typename CharT, size_t N>
requires(N % 2 == 0)
shake256_value(const fixed_string<CharT, N> &) -> shake256_value<N * 4u>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_shake256() {
		return shake256_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

// xxhash (non-crypto fast hash)
#ifndef CTHASH_XXHASH_HPP
#define CTHASH_XXHASH_HPP

#include <array>
#include <span>
#include <string_view>
#include <cstdint>

namespace cthash {

template <size_t Bits> struct xxhash_types;

template <std::unsigned_integral T, byte_like Byte> constexpr auto read_le_number_from(std::span<const Byte> & input) noexcept {
	CTHASH_ASSERT(input.size() >= sizeof(T));

	const auto r = cast_from_le_bytes<T>(input.template first<sizeof(T)>());
	input = input.subspan(sizeof(T));

	return r;
}

template <std::unsigned_integral T, size_t Off, byte_like Byte, size_t N> constexpr auto get_le_number_from(std::span<const Byte, N> input) noexcept {
	return cast_from_le_bytes<T>(input.template subspan<Off * sizeof(T), sizeof(T)>());
}

template <> struct xxhash_types<32> {
	using value_type = uint32_t;
	using acc_array = std::array<value_type, 4>;
	static constexpr auto primes = std::array<value_type, 5>{2654435761U, 2246822519U, 3266489917U, 668265263U, 374761393U};

	static constexpr auto round(value_type accN, value_type laneN) noexcept -> value_type {
		return std::rotl(accN + (laneN * primes[1]), 13u) * primes[0];
	}

	static constexpr auto convergence(const acc_array & accs) noexcept -> value_type {
		return std::rotl(accs[0], 1u) + std::rotl(accs[1], 7u) + std::rotl(accs[2], 12u) + std::rotl(accs[3], 18u);
	}

	template <byte_like Byte> static constexpr auto consume_remaining(value_type acc, std::span<const Byte> input) noexcept -> value_type {
		CTHASH_ASSERT(input.size() < sizeof(acc_array));

		while (input.size() >= sizeof(uint32_t)) {
			const auto lane = read_le_number_from<uint32_t>(input);
			acc = std::rotl(acc + (lane * primes[2]), 17u) * primes[3];
		}

		while (input.size() >= 1u) {
			const auto lane = read_le_number_from<uint8_t>(input);
			acc = std::rotl(acc + lane * primes[4], 11u) * primes[0];
		}

		return acc;
	}

	static constexpr auto avalanche(value_type acc) noexcept -> value_type {
		acc = (acc xor (acc >> 15u)) * primes[1];
		acc = (acc xor (acc >> 13u)) * primes[2];
		return (acc xor (acc >> 16u));
	}
};

template <> struct xxhash_types<64> {
	using value_type = uint64_t;
	using acc_array = std::array<value_type, 4>;
	static constexpr auto primes = std::array<value_type, 5>{11400714785074694791ULL, 14029467366897019727ULL, 1609587929392839161ULL, 9650029242287828579ULL, 2870177450012600261ULL};

	static constexpr auto round(value_type accN, value_type laneN) noexcept -> value_type {
		return std::rotl(accN + (laneN * primes[1]), 31u) * primes[0];
	}

	static constexpr auto convergence(const acc_array & accs) noexcept -> value_type {
		constexpr auto merge = [](value_type acc, value_type accN) {
			return ((acc xor round(0, accN)) * primes[0]) + primes[3];
		};

		value_type acc = std::rotl(accs[0], 1u) + std::rotl(accs[1], 7u) + std::rotl(accs[2], 12u) + std::rotl(accs[3], 18u);
		acc = merge(acc, accs[0]);
		acc = merge(acc, accs[1]);
		acc = merge(acc, accs[2]);
		return merge(acc, accs[3]);
	}

	template <byte_like Byte> static constexpr auto consume_remaining(value_type acc, std::span<const Byte> input) noexcept -> value_type {
		CTHASH_ASSERT(input.size() < sizeof(acc_array));

		while (input.size() >= sizeof(uint64_t)) {
			const auto lane = read_le_number_from<uint64_t>(input);
			acc = (std::rotl(acc xor round(0, lane), 27u) * primes[0]) + primes[3];
		}

		if (input.size() >= sizeof(uint32_t)) {
			const auto lane = read_le_number_from<uint32_t>(input);
			acc = (std::rotl(acc xor (lane * primes[0]), 23u) * primes[1]) + primes[2];
		}

		while (input.size() >= 1u) {
			const auto lane = read_le_number_from<uint8_t>(input);
			acc = (std::rotl(acc xor (lane * primes[4]), 11u) * primes[0]);
		}

		return acc;
	}

	static constexpr auto avalanche(value_type acc) noexcept -> value_type {
		acc = (acc xor (acc >> 33u)) * primes[1];
		acc = (acc xor (acc >> 29u)) * primes[2];
		return (acc xor (acc >> 32u));
	}
};

template <size_t Bits> struct xxhash {
	static_assert(Bits == 32u || Bits == 64u);

	struct tag {
		static constexpr size_t digest_length = Bits / 8u;
	};

	using config = xxhash_types<Bits>;
	using acc_array = typename config::acc_array;
	using value_type = typename config::value_type;

	using digest_span_t = std::span<std::byte, Bits / 8u>;

	// members
	value_type seed{0u};
	value_type length{0u};
	acc_array internal_state{};
	std::array<std::byte, sizeof(value_type) * 4u> buffer{};

	// step 1 in constructor
	explicit constexpr xxhash(value_type s = 0u) noexcept: seed{s}, internal_state{seed + config::primes[0] + config::primes[1], seed + config::primes[1], seed, seed - config::primes[0]} { }

	template <byte_like Byte> constexpr void process_lanes(std::span<const Byte, sizeof(acc_array)> lanes) noexcept {
		// step 2: process lanes
		internal_state[0] = config::round(internal_state[0], get_le_number_from<value_type, 0>(lanes));
		internal_state[1] = config::round(internal_state[1], get_le_number_from<value_type, 1>(lanes));
		internal_state[2] = config::round(internal_state[2], get_le_number_from<value_type, 2>(lanes));
		internal_state[3] = config::round(internal_state[3], get_le_number_from<value_type, 3>(lanes));
	}

	constexpr size_t buffer_usage() const noexcept {
		return length % buffer.size();
	}

	template <byte_like Byte> constexpr void process_blocks(std::span<const Byte> & input) noexcept {
		while (input.size() >= buffer.size()) {
			const auto current_lanes = input.template first<sizeof(acc_array)>();
			input = input.subspan(buffer.size());

			process_lanes(current_lanes);
		}
	}

	template <byte_like Byte> [[gnu::flatten]] constexpr xxhash & update(std::span<const Byte> input) noexcept {
		const auto buffer_remaining = std::span(buffer).subspan(buffer_usage());

		// everything we insert here is counting as part of input (even if we process it later)
		length += static_cast<uint8_t>(input.size());

		// if there is remaining data from previous...
		if (buffer_remaining.size() != buffer.size()) {
			const auto to_copy = input.first(std::min(input.size(), buffer_remaining.size()));
			byte_copy(to_copy.begin(), to_copy.end(), buffer_remaining.begin());
			input = input.subspan(to_copy.size());

			// if we didn't fill current block, we will do it later
			if (buffer_remaining.size() != to_copy.size()) {
				CTHASH_ASSERT(input.size() == 0u);
				return *this;
			}

			// but if we did, we need to process it
			const auto full_buffer_view = std::span<const std::byte, sizeof(acc_array)>(buffer);
			process_lanes(full_buffer_view);
		}

		// process blocks
		process_blocks(input);

		// copy remainder of input to the buffer, so it's processed later
		byte_copy(input.begin(), input.end(), buffer.begin());
		return *this;
	}

	template <one_byte_char CharT> [[gnu::flatten]] constexpr xxhash & update(std::basic_string_view<CharT> input) noexcept {
		return update(std::span<const CharT>(input.data(), input.size()));
	}

	template <string_literal T> [[gnu::flatten]] constexpr xxhash & update(const T & input) noexcept {
		return update(std::span(std::data(input), std::size(input) - 1u));
	}

	template <byte_like Byte> [[gnu::flatten]] constexpr auto update_and_final(std::span<const Byte> input) noexcept {
		length = static_cast<value_type>(input.size());
		process_blocks(input);
		tagged_hash_value<tag> output;
		final_from(input, output);
		return output;
	}

	template <one_byte_char CharT> [[gnu::flatten]] constexpr auto update_and_final(std::basic_string_view<CharT> input) noexcept {
		return update_and_final(std::span<const CharT>(input.data(), input.size()));
	}

	template <string_literal T> [[gnu::flatten]] constexpr auto update_and_final(const T & input) noexcept {
		return update_and_final(std::span(std::data(input), std::size(input) - 1u));
	}

	constexpr auto converge_conditionaly() const noexcept -> value_type {
		// step 1 shortcut for short input
		if (length < buffer.size()) {
			return seed + config::primes[4];
		}

		// otherwise we need to merge&converge internal state
		return config::convergence(internal_state);
	}

	template <byte_like Byte> constexpr void final_from(std::span<const Byte> source, digest_span_t out) const noexcept {
		CTHASH_ASSERT(source.size() < buffer.size());

		value_type acc = converge_conditionaly();

		// step 4: add input length
		acc += static_cast<value_type>(length);

		// step 5: consume remainder (not finished block from buffer)
		acc = config::consume_remaining(acc, source);

		// step 6: final mix/avalanche
		acc = config::avalanche(acc);

		// convert to big endian representation
		unwrap_bigendian_number<value_type>{out} = acc;
	}

	[[gnu::flatten]] constexpr void final(digest_span_t out) const noexcept {
		const auto buffer_used = std::span<const std::byte>(buffer).first(buffer_usage());
		final_from(buffer_used, out);
	}

	[[gnu::flatten]] constexpr auto final() const noexcept -> tagged_hash_value<tag> {
		tagged_hash_value<tag> output;
		this->final(output);
		return output;
	}
};

using xxhash32 = cthash::xxhash<32>;
using xxhash32_value = tagged_hash_value<xxhash32::tag>;

using xxhash64 = cthash::xxhash<64>;
using xxhash64_value = tagged_hash_value<xxhash64::tag>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_xxh32() {
		return xxhash32_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_xxh64() {
		return xxhash64_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif

#endif
