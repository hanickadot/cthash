#include <cthash/sha2.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <iostream>

using namespace cthash::literals;

template <size_t N> consteval auto array_of_zero_bytes() {
	std::array<std::byte, N> output;
	for (std::byte & val: output) val = std::byte{0};
	return output;
}

TEST_CASE("sha224 basics") {
	constexpr auto v1 = cthash::sha224{}.update("").final();
	REQUIRE(v1 == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"_hash);
	REQUIRE(v1 == "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"_sha224);

	constexpr auto v2 = cthash::sha224{}.update("hana").final();
	REQUIRE(v2 == "a814c3122b1a3f2402bbcd0faffe28a9a7c24d389af78b596c752684"_hash);
	REQUIRE(v2 == "a814c3122b1a3f2402bbcd0faffe28a9a7c24d389af78b596c752684"_sha224);

	constexpr auto v3 = cthash::sha224{}.update(array_of_zero_bytes<32>()).final();
	REQUIRE(v3 == "b338c76bcffa1a0b3ead8de58dfbff47b63ab1150e10d8f17f2bafdf"_hash);
	REQUIRE(v3 == "b338c76bcffa1a0b3ead8de58dfbff47b63ab1150e10d8f17f2bafdf"_sha224);

	constexpr auto v4 = cthash::sha224{}.update(array_of_zero_bytes<64>()).final();
	REQUIRE(v4 == "750d81a39c18d3ce27ff3e5ece30b0088f12d8fd0450fe435326294b"_hash);
	REQUIRE(v4 == "750d81a39c18d3ce27ff3e5ece30b0088f12d8fd0450fe435326294b"_sha224);

	constexpr auto v5 = cthash::sha224{}.update(array_of_zero_bytes<120>()).final();
	REQUIRE(v5 == "83438028e7817c90b386a11c9a4e051f821b37c818bb4b5c08279584"_hash);
	REQUIRE(v5 == "83438028e7817c90b386a11c9a4e051f821b37c818bb4b5c08279584"_sha224);

	constexpr auto v6 = cthash::sha224{}.update(array_of_zero_bytes<128>()).final();
	REQUIRE(v6 == "2fbd823ebcd9909d265827e4bce793a4fc572e3f39c7c3dd67749f3e"_hash);
	REQUIRE(v6 == "2fbd823ebcd9909d265827e4bce793a4fc572e3f39c7c3dd67749f3e"_sha224);
}
