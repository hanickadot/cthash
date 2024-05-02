#include <cthash/encoding/base.hpp>
#include <cthash/sha3/sha3-256.hpp>
#include <iostream>

using namespace cthash::literals;

template <typename> struct identify;

int main() {
	constexpr auto a = cthash::sha3_256{}.update("hello there!").final();

	const auto b = a | cthash::base64_encode;

	std::cout << b << "\n";
}