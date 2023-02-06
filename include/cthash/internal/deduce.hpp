#ifndef CTHASH_INTERNAL_DEDUCE_HPP
#define CTHASH_INTERNAL_DEDUCE_HPP

#include <concepts>
#include <cstdint>

namespace cthash::internal {

// support

template <typename T> concept digest_length_provided = requires() //
{
	{ static_cast<size_t>(T::digest_length) } -> std::same_as<size_t>;
};

template <typename T> concept digest_length_bit_provided = requires() //
{
	{ static_cast<size_t>(T::digest_length_bit) } -> std::same_as<size_t>;
};

template <typename Config> struct deduce_digest_length_t {
	static constexpr size_t bytes = Config::initial_values.size() * sizeof(typename decltype(Config::initial_values)::value_type);
};

template <digest_length_provided Config> struct deduce_digest_length_t<Config> {
	static constexpr size_t bytes = static_cast<size_t>(Config::digest_length);
};

template <digest_length_bit_provided Config> struct deduce_digest_length_t<Config> {
	static_assert(Config::digest_length_bit % 8u == 0u);
	static constexpr size_t bytes = static_cast<size_t>(Config::digest_length_bit / 8u);
};

template <typename Config> constexpr size_t digest_bytes_length_of = deduce_digest_length_t<Config>::bytes;

} // namespace cthash::internal

#endif