#include <cthash/sha3/sha3-256.hpp>
#include <print>

using namespace cthash::literals;

int main() {
	constexpr auto a = cthash::sha3_256{}.update("hello there!").final();

	std::print("{:HEXDEC}", a);
}
