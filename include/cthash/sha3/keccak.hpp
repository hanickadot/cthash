#ifndef CTHASH_SHA3_KECCAK_HPP
#define CTHASH_SHA3_KECCAK_HPP

#include "common.hpp"

namespace cthash {

template <unsigned N> struct prenist_keccak_config {
	static constexpr size_t digest_length_bit = N;
	static constexpr size_t capacity_bit = digest_length_bit * 2u;
	static constexpr size_t rate_bit = 1600u - capacity_bit;

	// Keccak (pre-NIST) domain bit = 0x01
	static constexpr auto suffix = keccak_suffix(0, 0x00);
};

static_assert((prenist_keccak_config<256>::capacity_bit + prenist_keccak_config<256>::rate_bit) == 1600u);

using keccak_256 = cthash::keccak_hasher<prenist_keccak_config<256>>;
using keccak_256_value = tagged_hash_value<prenist_keccak_config<256>>;
using keccak_384 = cthash::keccak_hasher<prenist_keccak_config<384>>;
using keccak_384_value = tagged_hash_value<prenist_keccak_config<384>>;
using keccak_512 = cthash::keccak_hasher<prenist_keccak_config<512>>;
using keccak_512_value = tagged_hash_value<prenist_keccak_config<512>>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_keccak_256() {
		return keccak_256_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_keccak_384() {
		return keccak_384_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_keccak_512() {
		return keccak_512_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
