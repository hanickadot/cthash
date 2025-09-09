#include <cthash/cthash.hpp>
#include <iostream>

using namespace cthash::literals;

template <typename> struct identify;

int main() {
	const cthash::sha256_value y = "1d996e033d612d9af2b44b70061ee0e868bfd14c2dd90b129e1edeb7953e7985"_sha256;

	std::cout << (y | cthash::hexdec_encode) << '\n';
	std::cout << (y | cthash::base32_encode) << '\n';
	std::cout << (y | cthash::binary_encode) << '\n';
}