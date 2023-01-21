#include <cthash/sha2.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace cthash::literals;

template <size_t N> consteval auto array_of_zero_bytes() {
	std::array<std::byte, N> output;
	for (std::byte & val: output) val = std::byte{0};
	return output;
}

TEST_CASE("sha512 basics", "[!shouldfail]") {
	constexpr auto v1 = cthash::sha512{}.update("").final();
	REQUIRE(v1 == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"_sha512);

	constexpr auto v2 = cthash::sha512{}.update("hana").final();
	REQUIRE(v2 == "74d15692038cd747dce0f4ff287ce1d5a7930c7e5948183419584f142039b3b25a94d1bf7f321f2fd2da37af1b6552f3e5bfc6c40d0bd8e16ecde338ee153a02"_sha512);

	constexpr auto v3 = cthash::sha512{}.update(array_of_zero_bytes<96>()).final();
	REQUIRE(v3 == "e866b15da9e5b18d4b3bde250fc08a208399440f37471313c5b4006e4151b0f4464b2cd7246899935d58660c0749cd11570bb8240760a6e46bb175be18cdaffe"_sha512);

	constexpr auto v4 = cthash::sha512{}.update(array_of_zero_bytes<120>()).final();
	REQUIRE(v4 == "c106c47ad6eb79cd2290681cb04cb183effbd0b49402151385b2d07be966e2d50bc9db78e00bf30bb567ccdd3a1c7847260c94173ba215a0feabb0edeb643ff0"_sha512);

	constexpr auto v5 = cthash::sha512{}.update(array_of_zero_bytes<128>()).final();
	REQUIRE(v5 == "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11"_sha512);
}
