#include <cthash/sha2/sha256.hpp>
#include <print>

using namespace cthash::literals;

int main() {
	constexpr auto a = cthash::sha256{}.update("hello there!").final();

	std::print("{}", a);
}
