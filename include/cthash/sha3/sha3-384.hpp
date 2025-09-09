#ifndef CTHASH_SHA3_SHA3_384_HPP
#define CTHASH_SHA3_SHA3_384_HPP

#include "common.hpp"

namespace cthash {

using sha3_384_config = sha_config<384u>;
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
