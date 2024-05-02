#include <cthash/encoding/base.hpp>
#include <cthash/sha3/sha3-256.hpp>
#include <iostream>

using namespace cthash::literals;

template <typename> struct identify;

int main() {
	std::println("{}", "hello there" | cthash::z_base32_encode);

	constexpr auto a = cthash::sha3_256{}.update("hello there!").final();
	std::println("{:base64url}", a);
}