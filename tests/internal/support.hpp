#ifndef CTHASH_TESTS_INTERNAL_SUPPORT_HPP
#define CTHASH_TESTS_INTERNAL_SUPPORT_HPP

#include <array>
#include <cstddef>

template <typename T> decltype(auto) runtime_pass(T && val) {
	return val;
}

template <size_t N, typename T = std::byte> consteval auto array_of(T value) {
	std::array<T, N> output;
	for (T & val: output) val = value;
	return output;
}

template <size_t N, typename T = std::byte> consteval auto array_of_zeros() {
	return array_of<N, T>(T{0});
}

#endif
