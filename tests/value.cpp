#include <cthash/value.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace cthash::literals;

TEST_CASE("hash_value (basics)") {
	constexpr auto v1 = cthash::hash_value{"0011223300112233"};
	constexpr auto v2 = cthash::hash_value{"00112233aabbccdd"};

	STATIC_REQUIRE(v1 < v2);
	STATIC_REQUIRE(v2 > v1);
	STATIC_REQUIRE(v1 != v2);

	constexpr auto v3 = cthash::hash_value{u8"00112233aabbccdd"};

	STATIC_REQUIRE(v1 != v2);
	STATIC_REQUIRE(v2 == v3);

	constexpr auto v4 = "599ba25a0d7c7d671bee93172ca7e272fc87f0c0e02e44df9e9436819067ea28"_hash;
	constexpr auto v5 = "00112233aabbccdd"_hash;

	STATIC_REQUIRE(v5 == v3);

	// constexpr bool comparable = requires(cthash::hash_value<8> l, cthash::hash_value<4> r) { v1 == v2; };
}