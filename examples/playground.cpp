#include <cthash/cthash.hpp>
#include <iostream>

using namespace cthash::literals;

template <typename> struct identify;

int main() {
	const auto r = cthash::sha256{}.update("hello").update("there").final();
	std::cout << r << "\n";
}