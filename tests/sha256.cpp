#include <cthash/sha2.hpp>
#include <catch2/catch_test_macros.hpp>

template <size_t N> consteval auto array_of_zero_bytes() {
	std::array<std::byte, N> output;
	for (std::byte & val: output) val = std::byte{0};
	return output;
}

TEST_CASE("sha256 basics") {
	using namespace cthash::literals;

	constexpr auto v1 = cthash::sha256{}.update("").final();
	CAPTURE(v1);
	REQUIRE(v1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_hash);
	REQUIRE(v1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_sha256);

	constexpr auto v2 = cthash::sha256{}.update("hana").final();
	CAPTURE(v2);
	REQUIRE(v2 == "599ba25a0d7c7d671bee93172ca7e272fc87f0c0e02e44df9e9436819067ea28"_hash);
	REQUIRE(v2 == "599ba25a0d7c7d671bee93172ca7e272fc87f0c0e02e44df9e9436819067ea28"_sha256);

	constexpr auto v3 = cthash::sha256{}.update(array_of_zero_bytes<96>()).final();
	CAPTURE(v3);
	REQUIRE(v3 == "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"_hash);
	REQUIRE(v3 == "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"_sha256);

	// constexpr auto v4 = cthash::sha256{}.update(array_of_zero_bytes<120>()).final();
	// STATIC_REQUIRE(v4 == "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"_hash);
	// STATIC_REQUIRE(v4 == "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"_sha256);

	constexpr auto v5 = cthash::sha256{}.update(array_of_zero_bytes<128>()).final();
	CAPTURE(v5);
	REQUIRE(v5 == "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca"_hash);
	REQUIRE(v5 == "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca"_sha256);
}