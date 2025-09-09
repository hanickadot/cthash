#ifndef CTHASH_SHA3_SHA3_HPP
#define CTHASH_SHA3_SHA3_HPP

#include "common.hpp"

namespace cthash {

using sha3_224_config = sha_config<224u>;
static_assert((sha3_224_config::capacity_bit + sha3_224_config::rate_bit) == 1600u);

using sha3_256_config = sha_config<256u>;
static_assert((sha3_256_config::capacity_bit + sha3_256_config::rate_bit) == 1600u);

using sha3_384_config = sha_config<384u>;
static_assert((sha3_384_config::capacity_bit + sha3_384_config::rate_bit) == 1600u);

using sha3_512_config = sha_config<512u>;
static_assert((sha3_512_config::capacity_bit + sha3_512_config::rate_bit) == 1600u);

// hasher and value type
using sha3_224 = cthash::keccak_hasher<sha3_224_config>;
using sha3_224_value = tagged_hash_value<sha3_224_config>;
using sha3_256 = cthash::keccak_hasher<sha3_256_config>;
using sha3_256_value = tagged_hash_value<sha3_256_config>;
using sha3_384 = cthash::keccak_hasher<sha3_384_config>;
using sha3_384_value = tagged_hash_value<sha3_384_config>;
using sha3_512 = cthash::keccak_hasher<sha3_512_config>;
using sha3_512_value = tagged_hash_value<sha3_512_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_224() {
		return sha3_224_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_sha3_256() {
		return sha3_256_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_sha3_384() {
		return sha3_384_value(Value);
	}

	template <fixed_string Value>
	consteval auto operator""_sha3_512() {
		return sha3_512_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
