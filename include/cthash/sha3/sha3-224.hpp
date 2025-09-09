#ifndef CTHASH_SHA3_SHA3_224_HPP
#define CTHASH_SHA3_SHA3_224_HPP

#include "common.hpp"

namespace cthash {

using sha3_224_config = sha_config<224u>;
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
