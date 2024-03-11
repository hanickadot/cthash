#ifndef CTHASH_ENCODING_BIT_BUFFER_HPP
#define CTHASH_ENCODING_BIT_BUFFER_HPP

#include "concepts.hpp"
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
