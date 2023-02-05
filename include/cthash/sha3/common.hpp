#ifndef CTHASH_SHA3_COMMON_HPP
#define CTHASH_SHA3_COMMON_HPP

#include "keccak.hpp"
#include "../hasher.hpp"
#include "../value.hpp"
#include <iomanip>
#include <iostream>

namespace cthash {

template <typename T, typename Y> concept castable_to = requires(T val) { {static_cast<Y>(val)} -> std::same_as<Y>; };

template <size_t N> struct keccak_suffix {
	unsigned bits;
	std::array<std::byte, N> values;

	constexpr keccak_suffix(unsigned b, castable_to<std::byte> auto... v) noexcept: bits{b}, values{static_cast<std::byte>(v)...} { }
};

template <castable_to<std::byte>... Ts> keccak_suffix(unsigned, Ts...) -> keccak_suffix<sizeof...(Ts)>;

template <size_t N> struct block_buffer {
	std::array<std::byte, N> storage{};
	unsigned used_bytes{0u};

	constexpr size_t size() const noexcept {
		return used_bytes;
	}

	constexpr size_t free_capacity() const noexcept {
		CTHASH_ASSERT(used_bytes < N);
		return N - used_bytes;
	}

	constexpr bool empty() const noexcept {
		return size() == 0u;
	}

	constexpr bool full() const noexcept {
		return size() == N;
	}

	constexpr void clear() noexcept {
		used_bytes = 0u;
	}

	constexpr auto remaining_space() noexcept -> std::span<std::byte> {
		return std::span<std::byte, N>(storage).subspan(used_bytes);
	}

	template <byte_like T> constexpr void eat_input_and_copy_into_remaining_space(std::span<const T> & input) noexcept {
		const auto remaining = remaining_space();
		const auto usable = input.first((std::min)(input.size(), remaining.size()));
		input = input.subspan(usable.size());

		byte_copy(usable.begin(), usable.end(), remaining.begin());
		used_bytes += usable.size();
	}

	template <byte_like T> constexpr void copy_into_empty_buffer(std::span<const T> input) noexcept {
		CTHASH_ASSERT(empty());
		CTHASH_ASSERT(input.size() <= N);
		byte_copy(input.begin(), input.end(), storage.begin());
		used_bytes += input.size();
	}
};

template <typename T> constexpr auto cast_from_le_bytes(std::span<const std::byte, sizeof(T)> in) noexcept {
	if (std::is_constant_evaluated()) {
		return [&]<size_t... Idx>(std::index_sequence<Idx...>) {
			return ((static_cast<T>(in[Idx]) << (Idx * 8u)) | ...);
		}
		(std::make_index_sequence<sizeof(T)>());
	} else {
		return std::bit_cast<T>(in.data());
	}
}

template <typename T, byte_like Byte> constexpr auto cast_from_le_bytes(std::span<const Byte, sizeof(T)> in) noexcept {
	return [&]<size_t... Idx>(std::index_sequence<Idx...>) {
		return ((static_cast<T>(in[Idx]) << (Idx * 8u)) | ...);
	}
	(std::make_index_sequence<sizeof(T)>());
}

template <std::unsigned_integral T> struct unwrap_littleendian_number {
	static constexpr size_t bytes = sizeof(T);
	static constexpr size_t bits = bytes * 8u;

	std::span<std::byte, bytes> ref;

	constexpr void operator=(T value) noexcept {
		[&]<size_t... Idx>(std::index_sequence<Idx...>) {
			((ref[Idx] = static_cast<std::byte>(value >> (Idx * 8u))), ...);
		}
		(std::make_index_sequence<bytes>());
	}
};

unwrap_littleendian_number(std::span<std::byte, 8>)->unwrap_littleendian_number<uint64_t>;
unwrap_littleendian_number(std::span<std::byte, 4>)->unwrap_littleendian_number<uint32_t>;

template <typename T> struct identify;

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
	block_buffer<rate> buffer;

	constexpr basic_keccak_hasher() noexcept {
		std::fill(internal_state.begin(), internal_state.end(), uint64_t{0});
	}

	// inserting blocks of `rate` into the hash internal state
	template <byte_like T> constexpr auto absorb(std::span<const T, rate> input) noexcept {
		using value_t = keccak::state_1600::value_type;

		// fill the `rate` part
		static_assert(rate % sizeof(value_t) == 0u);

		for (int i = 0; i < int(rate); i += sizeof(value_t)) {
			const auto part = input.subspan(size_t(i)).template first<sizeof(value_t)>();
			const value_t v = cast_from_le_bytes<value_t>(part);

			internal_state[i / sizeof(value_t)] ^= v;
		}

		// filling `capacity` part is no-op

		// and call keccak
		keccak_f(internal_state);
	}

	constexpr auto absorb(std::span<const std::byte, rate> input) noexcept {
		return absorb<std::byte>(input);
	}

	template <byte_like T> constexpr auto update(std::span<const T> input) noexcept {
		// TODO replace with direct absorbing
		if (not buffer.empty()) {
			buffer.eat_input_and_copy_into_remaining_space(input);
			if (buffer.full()) {
				absorb(buffer.storage);
				buffer.clear();
			}
		}

		while (input.size() >= rate) {
			// process `rate` at once
			const auto block = input.template first<rate>();
			input = input.subspan(rate);

			absorb(block);
		}

		// TODO replace with direct absorbing
		if (not input.empty()) {
			buffer.copy_into_empty_buffer(input);
			CTHASH_ASSERT(!buffer.full());
		}
	}

	// pad the message
	constexpr void final_absorb() noexcept {
		// TODO support longer suffixes
		CTHASH_ASSERT(!buffer.full());

		const auto suffix_and_padding = buffer.remaining_space();

		constexpr const auto & suffix = Config::suffix;
		static_assert(suffix.values.size() == 1u, "longer suffix is not implemented");
		CTHASH_ASSERT(Config::suffix.bits <= 5);

		// this technically never happen with SHA-3
		CTHASH_ASSERT((suffix_and_padding.size() * 8u) >= (Config::suffix.bits + 2u));

		// zero out buffer
		// TODO replace with direct absorbing
		std::fill(suffix_and_padding.begin(), suffix_and_padding.end(), std::byte{0});

		// front and back can be the same
		suffix_and_padding.front() = suffix.values[0] | (std::byte{0b0000'0001u} << suffix.bits);
		suffix_and_padding.back() |= std::byte{0b1000'0000u};

		absorb(buffer.storage);
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
	requires(digest_length < rate)
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

	constexpr void final(digest_span_t digest) noexcept {
		final_absorb();
		squeeze(digest);
	}

	constexpr result_t final() noexcept {
		result_t output;
		final(output);
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
