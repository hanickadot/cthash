#include <cthash/cthash.hpp>
#include <iostream>

int main(int argc, char ** argv) {
	std::cout << "    sha224 = " << cthash::sha224{}.update(std::string_view(argv[1])).final() << "\n";
	std::cout << "    sha256 = " << cthash::sha256{}.update(std::string_view(argv[1])).final() << "\n";
	std::cout << "    sha384 = " << cthash::sha384{}.update(std::string_view(argv[1])).final() << "\n";
	std::cout << "    sha512 = " << cthash::sha512{}.update(std::string_view(argv[1])).final() << "\n";
	std::cout << "sha512/224 = " << cthash::sha512t<224>{}.update(std::string_view(argv[1])).final() << "\n";
	std::cout << "sha512/256 = " << cthash::sha512t<256>{}.update(std::string_view(argv[1])).final() << "\n";
}