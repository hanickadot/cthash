#include "../internal/support.hpp"
#include <cthash/sha3/sha3-256.hpp>
#include <catch2/catch_test_macros.hpp>
#include <iostream>

using namespace cthash::literals;

TEST_CASE("sha3-256 basics") {
	const auto a = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"_sha3_256;
	REQUIRE(a.size() == 256u / 8u);
}

TEST_CASE("sha3-256 test strings") {
	SECTION("empty") {
		const auto r0 = cthash::sha3_256().update("").final();
		REQUIRE(r0 == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"_sha3_256);
	}

	SECTION("empty with bytes") {
		const auto r0 = cthash::sha3_256().update(std::span<const std::byte>()).final();
		REQUIRE(r0 == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"_sha3_256);
	}

	SECTION("test") {
		const auto r0 = cthash::sha3_256().update("test").final();
		REQUIRE(r0 == "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"_sha3_256);
	}

	SECTION("hanicka") {
		const auto r0 = cthash::sha3_256().update("hanicka").final();
		REQUIRE(r0 == "8f8b0b8af4c371e91791b1ddb2d0788661dd687060404af6320971bcc53b44fb"_sha3_256);
	}

	SECTION("*136 characters (exactly block size)") {
		auto in = std::string(size_t(136), '*'); // size of block
		const auto r0 = cthash::sha3_256().update(in).final();
		REQUIRE(r0 == "5224abc95021feafd89e36b41067884a08b39ff8e5ce0905c3a67d1857169e8a"_sha3_256);
	}

	SECTION("*137 characters (exactly block + 1 size)") {
		auto in = std::string(size_t(137), '*'); // size of block + 1
		const auto r0 = cthash::sha3_256().update(in).final();
		REQUIRE(r0 == "596fe83ba2cb6199c98be88ca31fc21511e0e7244465c0bdfece933e9daa59bd"_sha3_256);
	}

	SECTION("*2500 characters") {
		auto in = std::string(size_t(2500), '*'); // size of block + 1
		const auto r0 = cthash::sha3_256().update(in).final();
		REQUIRE(r0 == "d406a008de11740c60173ea37a9c67d4f1dea8fbfc3a41a2cbef8037b32e7541"_sha3_256);
	}

	SECTION("*2500 by one") {
		auto h = cthash::sha3_256();
		for (int i = 0; i != 2500; ++i) {
			h.update("*");
		}
		const auto r0 = h.final();
		REQUIRE(r0 == "d406a008de11740c60173ea37a9c67d4f1dea8fbfc3a41a2cbef8037b32e7541"_sha3_256);
	}
}