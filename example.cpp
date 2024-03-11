#include <cthash/cthash.hpp>
#include <print>

int main(int argc, char ** argv) {
	if (argc < 2) {
		return 1;
	}

	const auto in = std::string_view(argv[1]);

	std::print("        sha224 = {:hexdec}\n", cthash::sha224{}.update(in).final());
	std::print("        sha256 = {:hexdec}\n", cthash::sha256{}.update(in).final());
	std::print("        sha384 = {:hexdec}\n", cthash::sha384{}.update(in).final());
	std::print("        sha512 = {:hexdec}\n", cthash::sha512{}.update(in).final());
	std::print("    sha512/224 = {:hexdec}\n", cthash::sha512t<224>{}.update(in).final());
	std::print("    sha512/256 = {:hexdec}\n", cthash::sha512t<256>{}.update(in).final());

	std::print("      sha3-224 = {:hexdec}\n", cthash::sha3_224{}.update(in).final());
	std::print("      sha3-256 = {:hexdec}\n", cthash::sha3_256{}.update(in).final());
	std::print("      sha3-384 = {:base64url}\n", cthash::sha3_384{}.update(in).final());
	std::print("      sha3-512 = {:base64url}\n", cthash::sha3_512{}.update(in).final());

	std::print("shake-128/64   = {:base64url}\n", cthash::shake128{}.update(in).final<64>());
	std::print("shake-128/128  = {:base64url}\n", cthash::shake128{}.update(in).final<128>());
	std::print("shake-128/1024 = {:base64url}\n", cthash::shake128{}.update(in).final<1024>());

	std::print("shake-256/64   = {:base64url}\n", cthash::shake256{}.update(in).final<64>());
	std::print("shake-256/128  = {:base64url}\n", cthash::shake256{}.update(in).final<128>());
	std::print("shake-256/1024 = {:base64url}\n", cthash::shake256{}.update(in).final<1024>());

	std::print("      xxhash32 = {:hexdec}\n", cthash::xxhash32{}.update(in).final());
	std::print("      xxhash64 = {:hexdec}\n", cthash::xxhash64{}.update(in).final());
}