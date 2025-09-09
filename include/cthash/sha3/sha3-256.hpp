#ifndef CTHASH_SHA3_SHA3_256_HPP
#define CTHASH_SHA3_SHA3_256_HPP

#include "common.hpp"

namespace cthash {

using sha3_256_config = sha_config<256u>;
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
