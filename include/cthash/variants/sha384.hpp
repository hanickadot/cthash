#ifndef CTHASH_VARIANTS_SHA384_HPP
#define CTHASH_VARIANTS_SHA384_HPP

#include "sha512.hpp"

namespace cthash {

struct sha384_config: sha512_config {
	static constexpr size_t digest_length = 48u;

	static constexpr auto initial_values = std::array<uint64_t, 8>{0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull, 0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull};

	static constexpr size_t values_for_output = 6u;
};

using sha384 = hasher<sha384_config>;
using sha384_value = tagged_hash_value<sha384_config>;

namespace literals {

	template <internal::fixed_string Value>
	consteval auto operator""_sha384() {
		return sha384_value(Value);
	}

} // namespace literals

} // namespace cthash

#endif
