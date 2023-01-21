#ifndef CONSTEXPR_SHA2_SHA2_HPP
#define CONSTEXPR_SHA2_SHA2_HPP

#include "value.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <span>
#include <cassert>
#include <concepts>
#include <cstdint>

namespace cthash {

struct sha256_config {
	static constexpr size_t block_bits = 512u;
	static constexpr size_t digest_length = 32u;

	// internal state
	static constexpr auto initial_values = std::array<uint32_t, 8>{
		// h_0 ... h_8
		0x6a09e667ul,
		0xbb67ae85ul,
		0x3c6ef372ul,
		0xa54ff53aul,
		0x510e527ful,
		0x9b05688cul,
		0x1f83d9abul,
		0x5be0cd19ul,
	};

	// staging buffer type
	using staging_type = uint32_t;
	static constexpr size_t staging_size = 64zu;

	// constants for rounds (same type as staging)
	static constexpr int rounds_number = 64;
	static constexpr auto constants = std::array<staging_type, staging_size>{// k[64]
		0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
		0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
		0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul, 0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
		0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
		0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
		0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
		0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
		0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul, 0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul};
};

template <typename T> concept one_byte_char = (sizeof(T) == 1zu);

template <typename T> concept byte_like = (sizeof(T) == 1zu) && (std::same_as<T, char> || std::same_as<T, unsigned char> || std::same_as<T, char8_t> || std::same_as<T, std::byte> || std::same_as<T, uint8_t> || std::same_as<T, int8_t>);

template <typename T> concept string_literal = requires(const T & in) //
{
	[]<one_byte_char CharT, size_t N>(const CharT(&)[N]) {}(in);
};

template <typename T> concept convertible_to_byte_span = requires(T && obj) //
{
	{ std::span(obj) };
	requires byte_like<typename decltype(std::span(obj))::value_type>;
	requires !string_literal<T>;
};

template <typename It1, typename It2, typename It3> constexpr auto byte_copy(It1 first, It2 last, It3 destination) {
	return std::transform(first, last, destination, [](byte_like auto v) { return static_cast<std::byte>(v); });
}

template <std::unsigned_integral T> struct unwrap_bigendian_number {
	static constexpr size_t bytes = sizeof(T);
	static constexpr size_t bits = bytes * 8zu;

	std::span<std::byte, bytes> ref;

	constexpr void operator=(T value) noexcept {
		[&]<size_t... Idx>(std::index_sequence<Idx...>) {
			((ref[Idx] = static_cast<std::byte>(value >> ((bits - 8zu) - 8zu * Idx))), ...);
		}
		(std::make_index_sequence<bytes>());
	}
};

unwrap_bigendian_number(std::span<std::byte, 8>)->unwrap_bigendian_number<uint64_t>;
unwrap_bigendian_number(std::span<std::byte, 4>)->unwrap_bigendian_number<uint32_t>;

template <typename T> constexpr auto cast_from_bytes(std::span<const std::byte, sizeof(T)> in) noexcept {
	return [&]<size_t... Idx>(std::index_sequence<Idx...>) {
		return ((static_cast<T>(in[Idx]) << ((sizeof(T) - 1zu - Idx) * 8zu)) | ...);
	}
	(std::make_index_sequence<sizeof(T)>());
}
/*
void dump_block(std::span<const std::byte> in) {
	std::cout << "-------\n";
	for (int i = 0; i != (int)in.size(); ++i) {
		const auto v = in[i];
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)v << ' ';
		if (i % 4 == 3) std::cout << "\n";
	}
	std::cout << "-------\n";
}

void dump_block(std::span<const uint32_t> in) {
	std::cout << "-------\n";
	for (int i = 0; i != (int)in.size(); ++i) {
		std::cout << i << " = " << std::bitset<32>(in[i]) << "\n";
	}
	std::cout << "-------\n";
}
*/

template <typename Config> struct internal_hasher {
	static constexpr auto config = Config{};
	static constexpr size_t block_size_bytes = config.block_bits / 8zu;

	// internal types
	using state_value_t = std::remove_cvref_t<decltype(Config::initial_values)>;

	using block_value_t = std::array<std::byte, block_size_bytes>;
	using block_view_t = std::span<const std::byte, block_size_bytes>;

	using staging_item_t = typename Config::staging_type;
	using staging_value_t = std::array<staging_item_t, config.staging_size>;
	using staging_view_t = std::span<const staging_item_t, config.staging_size>;

	using digest_span_t = std::span<std::byte, config.digest_length>;
	using result_t = cthash::tagged_hash_value<Config>;

	// internal state
	state_value_t hash;
	uint64_t total_length;

	block_value_t block;
	unsigned block_used;

	// constructors
	constexpr internal_hasher() noexcept: hash{config.initial_values}, total_length{0zu}, block_used{0u} { }
	constexpr internal_hasher(const internal_hasher &) noexcept = default;
	constexpr internal_hasher(internal_hasher &&) noexcept = default;
	constexpr ~internal_hasher() noexcept = default;

	static constexpr auto prepare_staging(block_view_t chunk) noexcept -> staging_value_t {
		[[clang::uninitialized]] staging_value_t w;

		constexpr auto first_part_size = block_size_bytes / sizeof(staging_item_t);

		// fill first part with chunk
		for (int i = 0; i != int(first_part_size); ++i) {
			w[i] = cast_from_bytes<staging_item_t>(chunk.subspan(i * sizeof(staging_item_t)).template first<sizeof(staging_item_t)>());
		}

		// fill the rest (generify)
		for (int i = int(first_part_size); i != int(config.staging_size); ++i) {
			const staging_item_t s0 = std::rotr(w[i - 15], 7) xor std::rotr(w[i - 15], 18) xor (w[i - 15] >> 3);
			const staging_item_t s1 = std::rotr(w[i - 2], 17) xor std::rotr(w[i - 2], 19) xor (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		return w;
	}

	static constexpr void rounds(staging_view_t w, state_value_t & state) noexcept {
		// create copy of internal state
		auto wvar = state_value_t(state);

		// just give them names
		auto & a = wvar[0];
		auto & b = wvar[1];
		auto & c = wvar[2];
		auto & d = wvar[3];
		auto & e = wvar[4];
		auto & f = wvar[5];
		auto & g = wvar[6];
		auto & h = wvar[7];

		for (int i = 0; i != config.rounds_number; ++i) {
			const uint32_t S1 = std::rotr(e, 6) xor std::rotr(e, 11) xor std::rotr(e, 25);
			const uint32_t choice = (e bitand f) xor (~e bitand g);
			const uint32_t temp1 = h + S1 + choice + config.constants[i] + w[i];

			const uint32_t S0 = std::rotr(a, 2) xor std::rotr(a, 13) xor std::rotr(a, 22);
			const uint32_t majority = (a bitand b) xor (a bitand c) xor (b bitand c);
			const uint32_t temp2 = S0 + majority;

			// move around
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// add store back
		for (int i = 0; i != (int)state.size(); ++i) {
			// std::cout << "h" << i << " = " << std::bitset<32>(hash[i]) << " + " << std::bitset<32>(wvar[i]) << " = " << std::bitset<32>(hash[i] + wvar[i]) << "\n";
			state[i] += wvar[i];
		}
	}

	// this implementation works only with input size aligned to bytes (not bits)
	template <byte_like T> constexpr void update_to_buffer_and_process(std::span<const T> in) noexcept {
		for (;;) {
			const auto remaining_free_space = std::span<std::byte, block_size_bytes>(block).subspan(block_used);
			const auto to_copy = in.first(std::min(in.size(), remaining_free_space.size()));

			const auto it = byte_copy(to_copy.begin(), to_copy.end(), remaining_free_space.begin());

			total_length += to_copy.size();

			if (it != remaining_free_space.end()) {
				block_used += to_copy.size();
				return;
			} else {
				block_used = 0zu;
			}

			assert(it == remaining_free_space.end());

			// we have block!
			const staging_value_t w = prepare_staging(block);
			rounds(w, hash);

			// continue with the next block (if there is any)
			in = in.subspan(to_copy.size());
			// TODO maybe avoid copying the data and process it directly over span
		}

		return;
	}

	static constexpr auto modify_and_add_padding(block_value_t & block, unsigned used, size_t total_length) noexcept -> block_view_t {
		// TODO fixme?
		const auto remaining_free_space = std::span(block).subspan(used);
		auto it = remaining_free_space.data();
		*it++ = std::byte{0b1000'0000u};
		std::fill(it, block.end(), std::byte{0x0u});
		unwrap_bigendian_number{remaining_free_space.template last<8>()} = (total_length * 8zu); // total length in bits at the end of last block
		return block;
	}

	constexpr void finalize_buffer() noexcept {
		const staging_value_t w = prepare_staging(modify_and_add_padding(block, block_used, total_length));
		rounds(w, hash);
	}

	constexpr void write_result_into(digest_span_t out) noexcept {
		// copy result to byte result
		for (int i = 0; i != (int)hash.size(); ++i) {
			unwrap_bigendian_number<uint32_t>{out.subspan(i * 4).template first<4>()} = hash[i];
		}
	}
};

// this is a convinience type for nicer UX...
template <typename Config> struct hasher: private internal_hasher<Config> {
	using super = internal_hasher<Config>;
	using result_t = typename super::result_t;
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
		super::update_to_buffer_and_process(std::span(lit, std::size(lit) - 1zu));
		return *this;
	}

	// output (by reference or by value)
	constexpr void final(digest_span_t digest) noexcept {
		super::finalize_buffer();
		super::write_result_into(digest);
	}

	constexpr auto final() noexcept {
		result_t output;
		this->final(output);
		return output;
	}
};

using sha256 = hasher<sha256_config>;
using sha256_value = typename hasher<sha256_config>::result_t;

namespace literals {

	template <internal::fixed_string Value>
	consteval auto operator""_sha256() {
		return sha256_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
