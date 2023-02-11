#ifndef CTHASH_XXHASH_HPP
#define CTHASH_XXHASH_HPP

#include "internal/assert.hpp"
#include "internal/bit.hpp"
#include "internal/concepts.hpp"
#include "internal/convert.hpp"
#include <array>
#include <span>
#include <string_view>

namespace cthash {

template <size_t Bits> struct xxhash_types;

template <std::unsigned_integral T, byte_like Byte> constexpr auto read_le_number_from(std::span<const Byte> & input) noexcept {
	CTHASH_ASSERT(input.size() >= sizeof(T));

	const auto r = cast_from_le_bytes<T>(input.template first<sizeof(T)>());
	input = input.subspan(sizeof(T));

	return r;
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
	};

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
	};

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

template <size_t Bits, byte_like Byte> [[gnu::flatten]] constexpr auto xxhash(std::span<const Byte> input, typename xxhash_types<Bits>::value_type seed = 0u) {
	using config = xxhash_types<Bits>;
	using acc_array = typename config::acc_array;
	using value_type = typename config::value_type;
	constexpr auto & primes = config::primes;
	const auto original_size = input.size();

	value_type acc = 0u;

	if (input.size() < sizeof(acc_array)) {
		// step 1-3: skipped
		acc = seed + primes[4];

	} else {
		// step 1: initialization (same for both versions)
		auto accs = acc_array{
			seed + primes[0] + primes[1],
			seed + primes[1],
			seed + 0u,
			seed - primes[0],
		};

		// step 2: process stripes
		while (input.size() >= sizeof(acc_array)) {
			accs[0] = config::round(accs[0], read_le_number_from<value_type>(input));
			accs[1] = config::round(accs[1], read_le_number_from<value_type>(input));
			accs[2] = config::round(accs[2], read_le_number_from<value_type>(input));
			accs[3] = config::round(accs[3], read_le_number_from<value_type>(input));
		}

		// step 3: merge and convergence
		acc = config::convergence(accs);
	}

	// step 4: add input length
	acc += static_cast<value_type>(original_size);

	// step 5: consume remaining input
	acc = config::consume_remaining(acc, input);

	// step 6: final mix / avalanche
	acc = config::avalanche(acc);

	return acc;
}

template <size_t Bits, typename CharT> constexpr auto xxhash(std::basic_string_view<CharT> input, typename xxhash_types<Bits>::value_type seed = 0u) noexcept {
	return xxhash<Bits>(std::span<const CharT>(input.data(), input.size()), seed);
}

template <size_t Bits, string_literal T> constexpr auto xxhash(const T & literal, typename xxhash_types<Bits>::value_type seed = 0u) noexcept {
	return xxhash<Bits>(std::span(std::data(literal), std::size(literal) - 1u), seed);
}

template <size_t Bits, convertible_to_byte_span T> constexpr auto xxhash(const T & something, typename xxhash_types<Bits>::value_type seed = 0u) noexcept {
	return xxhash<Bits>(std::span(something), seed);
}

} // namespace cthash

#endif
