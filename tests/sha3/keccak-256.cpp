#include <catch2/catch_test_macros.hpp>
#include "../internal/support.hpp"
#include <cthash/sha3/keccak.hpp>
#include <iostream>

using namespace cthash::literals;

TEST_CASE("keccak-256 basics") {
	const auto a = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"_keccak_256;
	REQUIRE(a.size() == 256u / 8u);
}

TEST_CASE("keccak-256 test strings") {
	SECTION("empty") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("empty with bytes") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update(std::span<const std::byte>()).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"_keccak_256);
		REQUIRE(r0 == r1);
	}
	SECTION("one letter") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("a").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"_keccak_256);
		REQUIRE(r0 == r1);
	}
	SECTION("two letters") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("ab").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "67fad3bfa1e0321bd021ca805ce14876e50acac8ca8532eda8cbf924da565160"_keccak_256);
		REQUIRE(r0 == r1);
	}
	SECTION("test") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("test").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"_keccak_256);
		REQUIRE(r0 == r1);
	}
	SECTION("experiment") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("experiment").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "047dbe311ff69923d959629005cb27fb9d3c725f890180fb93365b03a25f0a58"_keccak_256);
		REQUIRE(r0 == r1);
	}
	SECTION("ethereum") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("Hello, Ethereum!").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "0a1e2723bd7f1996832b7ed7406df8ad975deba1aa04020b5bfc3e6fe70ecc29"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("hello world") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("Hello, world! Keccak-256 Hash").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "536c0a47629a8e5051078a4e01af79782e43cb62bd70b685fd5847a1ff0d4968"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("hanicka") {
		constexpr auto calculation = []() {
			return cthash::keccak_256().update("hanicka").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "9be9c6b5bc2daec3e078ec9ee811f878b4b101eb0981a63756f8c766bb367a6b"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("*136 characters (exactly block size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136), '*'); // size of block
			return cthash::keccak_256().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "e60d5160227cb1b8dc8547deb9c6a2c5e6c3306a1ca155611a73ed2c2324bfc0"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("*137 characters (exactly block + 1 size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136 + 1), '*'); // size of block
			return cthash::keccak_256().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "6c882042bcc30221e6461507497574e018538e65d2006f9b1137d13347e31ed9"_keccak_256);
		REQUIRE(r0 == r1);
	}

	SECTION("*2500 characters") {
		auto in = std::string(size_t(2500), '*'); // size of block + 1
		const auto r0 = cthash::keccak_256().update(in).final();
		REQUIRE(r0 == "8e123b2ca404436c18353fb7770c97485d1be96ca0730907fc523896aac95e12"_keccak_256);
	}

	SECTION("*2500 by one") {
		auto h = cthash::keccak_256();
		for (int i = 0; i != 2500; ++i) {
			h.update("*");
		}
		const auto r0 = h.final();
		REQUIRE(r0 == "8e123b2ca404436c18353fb7770c97485d1be96ca0730907fc523896aac95e12"_keccak_256);
	}
}

TEST_CASE("keccak-256 stability") {
	auto h = cthash::keccak_256();

	constexpr int end = int(h.rate) * 2;

	for (int i = 0; i != end; ++i) {
		const auto piece = std::string(size_t(i), '#');
		h.update(piece);
	}

	const auto r0 = h.final();
	REQUIRE(r0 == "9afd724feebce0415a9669f2003b27b510ff7d77d8ad50a31c590d8409efeb41"_keccak_256);
}

TEST_CASE("keccak-256 printing") {
	auto hash = cthash::keccak_256().final();
	std::ostringstream ss;
	ss << hash;

	REQUIRE(ss.str() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST_CASE("keccak-256 formatting") {
	auto hash = cthash::keccak_256().final();
	auto str = std::format("{}", hash);

	REQUIRE(str == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST_CASE("keccak-256 formatting (hexdec explicitly)") {
	auto hash = cthash::keccak_256().final();
	auto str = std::format("{:hexdec}", hash);

	REQUIRE(str == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

TEST_CASE("keccak-256 formatting (z_base32 explicitly)") {
	auto hash = cthash::keccak_256().final();
	auto str = std::format("{:zbase32}", hash);

	REQUIRE(str == "azjrcycg6htu3ru6xs3p3tadad1obp1u3kbnqq559mcyezcfwtay");
}

TEST_CASE("keccak-256 formatting (base64url explicitly)") {
	auto hash = cthash::keccak_256().update("hanicka").final();
	auto str = std::format("{:base64url}", hash);

	REQUIRE(str == "m-nGtbwtrsPgeOye6BH4eLSxAesJgaY3VvjHZrs2ems");
}

TEST_CASE("keccak-256 formatting (binary explicitly)") {
	auto hash = cthash::keccak_256().update("hanicka").final();
	auto str = std::format("{:binary}", hash);

	REQUIRE(str ==
		"1001101111101001110001101011010110111100001011011010111011000011111000000111"
		"1000111011001001111011101000000100011111100001111000101101001011000100000001"
		"1110101100001001100000011010011000110111010101101111100011000111011001101011"
		"1011001101100111101001101011");
}

template <typename Container = std::string> auto materialize(auto && range) {
	auto result = Container{};
	result.resize(range.size());
	auto [in, out] = std::ranges::copy(range, result.begin());
	REQUIRE(in == range.end());
	REQUIRE(out == result.end());
	return result;
}

TEST_CASE("static and dynamic path generates same results (keccak256)") {
	auto hash = cthash::keccak_256().update("hanicka").final();

	REQUIRE(std::format("{:base2}", hash) == materialize(hash | cthash::base2_encode));
	REQUIRE(std::format("{:binary}", hash) == materialize(hash | cthash::binary_encode));
	REQUIRE(std::format("{:base4}", hash) == materialize(hash | cthash::base4_encode));
	REQUIRE(std::format("{:base8}", hash) == materialize(hash | cthash::base8_encode));
	REQUIRE(std::format("{:octal}", hash) == materialize(hash | cthash::octal_encode));
	REQUIRE(std::format("{:base16}", hash) == materialize(hash | cthash::base16_encode));
	REQUIRE(std::format("{:hexdec}", hash) == materialize(hash | cthash::hexdec_encode));
	REQUIRE(std::format("{:base32}", hash) == materialize(hash | cthash::base32_encode));
	REQUIRE(std::format("{:base32_no_padding}", hash) == materialize(hash | cthash::base32_no_padding_encode));
	REQUIRE(std::format("{:z_base32}", hash) == materialize(hash | cthash::z_base32_encode));
	REQUIRE(std::format("{:base64}", hash) == materialize(hash | cthash::base64_encode));
	REQUIRE(std::format("{:base64url}", hash) == materialize(hash | cthash::base64url_encode));
	REQUIRE(std::format("{:base64_no_padding}", hash) == materialize(hash | cthash::base64_no_padding_encode));
}

TEST_CASE("keccak-256 formatting (shortening)") {
	auto hash = cthash::keccak_256().final();
	auto str = std::format("{:hexdec}..{:hexdec}", hash.prefix<3>(), hash.suffix<3>());

	REQUIRE(str == "c5d246..85a470");
}
