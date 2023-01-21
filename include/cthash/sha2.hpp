#ifndef CONSTEXPR_SHA2_SHA2_HPP
#define CONSTEXPR_SHA2_SHA2_HPP

#include <algorithm>
#include <array>
#include <bit>
#include <span>
#include <cassert>
#include <concepts>
#include <cstdint>

// TODO delete me
#include <bitset>
#include <iomanip>
#include <iostream>

namespace cthash {

namespace literals {

	consteval auto operator""_B(unsigned long long v) noexcept {
		return static_cast<std::byte>(v);
	}

} // namespace literals

struct sha256_config {
	static constexpr size_t block_size = 512u / 8u; // bytes
	static constexpr size_t digest_length = 32u;	// bytes

	// resulting value type
	using output_type = std::array<std::byte, digest_length>;

	// internal state
	static constexpr auto hash_init = std::array<uint32_t, 8>{
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

	static constexpr auto constants = std::array<uint32_t, 64>{// k[64]
		0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
		0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
		0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul, 0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
		0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
		0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
		0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
		0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
		0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul, 0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul};
};

template <typename T> concept byte_like = (sizeof(T) == 1zu) && (std::same_as<T, char> || std::same_as<T, unsigned char> || std::same_as<T, char8_t> || std::same_as<T, std::byte> || std::same_as<T, uint8_t> || std::same_as<T, int8_t>);

template <typename T> concept is_string_literal = requires(const T & in) //
{
	[]<typename CharT, size_t N>(const CharT(&)[N]) {}(in);
};

template <typename T> concept convertible_to_byte_span = requires(T && obj) //
{
	{ std::span(obj) };
	requires byte_like<typename decltype(std::span(obj))::value_type>;
	requires !is_string_literal<T>;
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

template <typename Config> struct hasher {
	static constexpr size_t block_size = Config::block_size;
	static constexpr size_t digest_length = Config::digest_length;

	using output_type = typename Config::output_type;

	using hash_state = std::remove_cvref_t<decltype(Config::hash_init)>;
	static constexpr auto & hash_init = Config::hash_init;
	static constexpr auto & constants = Config::constants;

	hash_state hash;

	std::array<std::byte, block_size> block;

	size_t block_used;
	size_t total_length;

	constexpr hasher() noexcept: hash{Config::hash_init}, block_used{0zu}, total_length{0zu} {
		// std::cout << "init...\n";
	}

	constexpr auto prepare_staging(std::span<const std::byte, Config::block_size> chunk) const noexcept -> std::array<uint32_t, 64> {
		[[clang::uninitialized]] std::array<uint32_t, 64> w;

		// fill first part with chunk
		for (int i = 0; i != 16; ++i) {
			w[i] = cast_from_bytes<uint32_t>(chunk.subspan(i * 4).template first<4>());
		}

		// fill the rest
		for (int i = 16; i != 64; ++i) {
			const uint32_t s0 = std::rotr(w[i - 15], 7) xor std::rotr(w[i - 15], 18) xor (w[i - 15] >> 3);
			const uint32_t s1 = std::rotr(w[i - 2], 17) xor std::rotr(w[i - 2], 19) xor (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		return w;
	}

	constexpr void rounds(std::span<const uint32_t, 64> w) noexcept {
		// create copy of internal state
		auto working_variables = hash_state(hash);

		// just give them names
		auto & a = working_variables[0];
		auto & b = working_variables[1];
		auto & c = working_variables[2];
		auto & d = working_variables[3];
		auto & e = working_variables[4];
		auto & f = working_variables[5];
		auto & g = working_variables[6];
		auto & h = working_variables[7];

		for (int i = 0; i != 64; ++i) {
			const uint32_t S1 = std::rotr(e, 6) xor std::rotr(e, 11) xor std::rotr(e, 25);
			const uint32_t choice = (e bitand f) xor (~e bitand g);
			const uint32_t temp1 = h + S1 + choice + constants[i] + w[i];

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
		for (int i = 0; i != (int)hash.size(); ++i) {
			// std::cout << "h" << i << " = " << std::bitset<32>(hash[i]) << " + " << std::bitset<32>(working_variables[i]) << " = " << std::bitset<32>(hash[i] + working_variables[i]) << "\n";
			hash[i] += working_variables[i];
		}
	}

	// this implementation works only with input size aligned to bytes (not bits)
	template <byte_like T> constexpr auto & update(std::span<const T> in) noexcept {
		for (;;) {
			const auto remaining_free_space = std::span<std::byte, block_size>(block).subspan(block_used);
			const auto to_copy = in.first(std::min(in.size(), remaining_free_space.size()));

			const auto it = byte_copy(to_copy.begin(), to_copy.end(), remaining_free_space.begin());

			total_length += to_copy.size();

			if (it != remaining_free_space.end()) {
				block_used += to_copy.size();
				break;
			} else {
				block_used = 0zu;
			}

			assert(it == remaining_free_space.end());

			// we have block!
			const std::array<uint32_t, 64> w = prepare_staging(block);
			rounds(w);
			block_used = 0zu;

			// continue with the next block (if there is any)
			in = in.subspan(to_copy.size());
			// TODO maybe avoid copying the data and process it directly over span
		}

		return *this;
	}

	constexpr void pad() noexcept {
		// TODO fixme?
		const auto remaining_free_space = std::span<std::byte, block_size>(block).subspan(block_used);
		auto it = remaining_free_space.data();
		*it++ = std::byte{0b1000'0000u};
		// std::cout << "distance = " << std::distance(it, remaining_free_space.data() + remaining_free_space.size()) << "\n";
		std::fill(it, block.end(), std::byte{0x0u});
		unwrap_bigendian_number{remaining_free_space.template last<8>()} = (total_length * 8zu); // total length in bits at the end of last block
	}

	template <convertible_to_byte_span T> constexpr auto & update(T && something) noexcept {
		using value_type = typename decltype(std::span(something))::value_type;
		return update(std::span<const value_type>(something));
	}

	template <typename CharT> constexpr auto & update(std::basic_string_view<CharT> in) noexcept {
		return update(std::span<const char>(in.data(), in.size()));
	}

	template <typename CharT, size_t N> constexpr auto & update(const CharT (&in)[N]) noexcept {
		return update(std::basic_string_view<CharT>(in, N - 1zu));
	}

	constexpr void final(std::span<std::byte, digest_length> out) noexcept {
		// std::cout << "final...\n";
		if (block_used >= (block.size() - 9zu)) {
			// TODO two blocks will be needed
			return; // :shrug:
		}

		pad();

		const std::array<uint32_t, 64> w = prepare_staging(block);
		rounds(w);

		// copy result to byte result
		for (int i = 0; i != (int)hash.size(); ++i) {
			unwrap_bigendian_number<uint32_t>{out.subspan(i * 4).template first<4>()} = hash[i];
		}
	}

	constexpr auto final() noexcept -> output_type {
		std::array<std::byte, digest_length> output;
		final(std::span<std::byte, digest_length>(output));
		return output;
	}
};

struct sha256: hasher<sha256_config> { };

} // namespace cthash

#endif
