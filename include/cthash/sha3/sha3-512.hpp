#ifndef CTHASH_SHA3_SHA3_512_HPP
#define CTHASH_SHA3_SHA3_512_HPP

#include "common.hpp"

namespace cthash {

using sha3_512_config = sha_config<512u>;
static_assert((sha3_512_config::capacity_bit + sha3_512_config::rate_bit) == 1600u);

using sha3_512 = cthash::keccak_hasher<sha3_512_config>;
using sha3_512_value = tagged_hash_value<sha3_512_config>;

namespace literals {

	template <fixed_string Value>
	consteval auto operator""_sha3_512() {
		return sha3_512_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
