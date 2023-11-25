#include <catch2/catch_test_macros.hpp>
#include "../internal/support.hpp"
#include <cthash/sha3/sha3-256.hpp>
#include <iostream>

using namespace cthash::literals;

TEST_CASE("sha3-256 basics") {
	const auto a = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"_sha3_256;
	REQUIRE(a.size() == 256u / 8u);
}

TEST_CASE("sha3-256 test strings") {
	SECTION("empty") {
		constexpr auto calculation = []() {
			return cthash::sha3_256().update("").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"_sha3_256);
		REQUIRE(r0 == r1);
	}

	SECTION("empty with bytes") {
		constexpr auto calculation = []() {
			return cthash::sha3_256().update(std::span<const std::byte>()).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"_sha3_256);
		REQUIRE(r0 == r1);
	}

	SECTION("test") {
		constexpr auto calculation = []() {
			return cthash::sha3_256().update("test").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"_sha3_256);
		REQUIRE(r0 == r1);
	}

	SECTION("hanicka") {
		constexpr auto calculation = []() {
			return cthash::sha3_256().update("hanicka").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "8f8b0b8af4c371e91791b1ddb2d0788661dd687060404af6320971bcc53b44fb"_sha3_256);
		REQUIRE(r0 == r1);
	}

	SECTION("*136 characters (exactly block size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136), '*'); // size of block
			return cthash::sha3_256().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "5224abc95021feafd89e36b41067884a08b39ff8e5ce0905c3a67d1857169e8a"_sha3_256);
		REQUIRE(r0 == r1);
	}

	SECTION("*137 characters (exactly block + 1 size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136 + 1), '*'); // size of block
			return cthash::sha3_256().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "596fe83ba2cb6199c98be88ca31fc21511e0e7244465c0bdfece933e9daa59bd"_sha3_256);
		REQUIRE(r0 == r1);
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

TEST_CASE("sha3-256 stability") {
	auto h = cthash::sha3_256();

	constexpr int end = int(h.rate) * 2;

	for (int i = 0; i != end; ++i) {
		const auto piece = std::string(size_t(i), '#');
		h.update(piece);
	}

	const auto r0 = h.final();
	REQUIRE(r0 == "af2e33605dbcb6f37facfcf7b999e068d25c38e12c86c33786cc207134812e6b"_sha3_256);
}

TEST_CASE("sha3-256 printing") {
	auto hash = cthash::sha3_256().final();
	std::ostringstream ss;
	ss << hash;

	REQUIRE(ss.str() == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST_CASE("sha3-256 formatting") {
	auto hash = cthash::sha3_256().final();
	auto str = std::format("{}", hash);

	REQUIRE(str == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST_CASE("sha3-256 formatting (hexdec explicitly)") {
	auto hash = cthash::sha3_256().final();
	auto str = std::format("{:hexdec}", hash);

	REQUIRE(str == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST_CASE("sha3-256 formatting (z_base32 explicitly)") {
	auto hash = cthash::sha3_256().final();
	auto str = std::format("{:zbase32}", hash);

	REQUIRE(str == "w99hp6f9d5mscwqbe7mkyaqscm4ab94pho7wu6wn5yfrzy8aepfy");
}

TEST_CASE("sha3-256 formatting (base64url explicitly)") {
	auto hash = cthash::sha3_256().update("hanicka").final();
	auto str = std::format("{:base64url}", hash);

	REQUIRE(str == "j4sLivTDcekXkbHdstB4hmHdaHBgQEr2MglxvMU7RPs");
}

TEST_CASE("sha3-256 formatting (binary explicitly)") {
	auto hash = cthash::sha3_256().update("hanicka").final();
	auto str = std::format("{:binary}", hash);

	REQUIRE(str ==
		"1000111110001011000010111000101011110100110000110111000111101001000101111001"
		"0001101100011101110110110010110100000111100010000110011000011101110101101000"
		"0111000001100000010000000100101011110110001100100000100101110001101111001100"
		"0101001110110100010011111011");
}

template <typename Container = std::string> auto materialize(auto && range) {
	auto result = Container{};
	result.resize(range.size());
	auto [in, out] = std::ranges::copy(range, result.begin());
	REQUIRE(in == range.end());
	REQUIRE(out == result.end());
	return result;
}

TEST_CASE("static and dynamic path generates same results") {
	auto hash = cthash::sha3_256().update("hanicka").final();

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

TEST_CASE("sha3-256 formatting (shortening)") {
	auto hash = cthash::sha3_256().final();
	auto str = std::format("{:hexdec}..{:hexdec}", hash.prefix<3>(), hash.suffix<3>());

	REQUIRE(str == "a7ffc6..f8434a");
}
