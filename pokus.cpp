#include <cthash/sha2.hpp>
#include <iomanip>
#include <string_view>
#include <iostream>

int main() {
	auto h = cthash::sha256{};
	h.update(std::string_view{""});
	// h.update(std::array<std::byte, 32>{});
	// h.update(std::array<std::byte, 16>{});
	// h.update(std::array<std::byte, 32>{});
	auto r = h.final();

	for (std::byte v: r) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)v;
	}
	std::cout << "\n";

	for (std::byte v: cthash::empty_sha256) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)v;
	}
	std::cout << "\n";
}