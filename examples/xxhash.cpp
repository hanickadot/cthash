#include <cthash/xxhash.hpp>
#include <print>

using namespace cthash::literals;

int main() {
	constexpr auto a = cthash::xxhash32{}.update("hello there!").final();

	std::print("{:base32}", a);
}
