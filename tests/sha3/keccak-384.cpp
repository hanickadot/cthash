#include <catch2/catch_test_macros.hpp>
#include "../internal/support.hpp"
#include <cthash/sha3/keccak.hpp>
#include <iostream>

using namespace cthash::literals;

TEST_CASE("keccak-384 basics") {
	const auto a = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"_keccak_384;
	REQUIRE(a.size() == 384u / 8u);
}

TEST_CASE("keccak-384 test strings") {
	SECTION("empty") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("empty with bytes") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update(std::span<const std::byte>()).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"_keccak_384);
		REQUIRE(r0 == r1);
	}
	SECTION("one letter") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("a").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "85e964c0843a7ee32e6b5889d50e130e6485cffc826a30167d1dc2b3a0cc79cba303501a1eeaba39915f13baab5abacf"_keccak_384);
		REQUIRE(r0 == r1);
	}
	SECTION("two letters") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("ab").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "d1112a0665627802eb0ff3225564b9cf6e99e1d58867a093095d16894e868549091d37e109da5c3bd671b39625e73591"_keccak_384);
		REQUIRE(r0 == r1);
	}
	SECTION("test") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("test").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527"_keccak_384);
		REQUIRE(r0 == r1);
	}
	SECTION("experiment") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("experiment").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "0f7777b310667f6bb0fae78815639f360590aa1cb81658ce8e907643bb67be725f15064347d871f5f64587545efca431"_keccak_384);
		REQUIRE(r0 == r1);
	}
	SECTION("ethereum") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("Hello, Ethereum!").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "756394287ae243a6c67ec0197ebdcd713d4b27e318c2f531fd40123948d2e768d516274e602c9eaafaa8f016037160ec"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("hello world") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("Hello, world! Keccak-384 Hash").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "e9ab8b2dd0ea09100a8646b8f72f67ac55074dbd9ab2a7446f585fa6275c4a3209b012a68e38fd4c57d11c446a02578d"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("hanicka") {
		constexpr auto calculation = []() {
			return cthash::keccak_384().update("hanicka").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "bf4d65386c7ea9b6a95f0b35acf81ebc1666e70470d6e8e3343073207af63ff7e2124d6e216a677acd650bb4f44b01fe"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("*136 characters (exactly block size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136), '*'); // size of block
			return cthash::keccak_384().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "767218950b7f7aea367e3d78b3866ebe0d2c9f890d27ec3350dd3b0d21ed109234d231e15da1ca6f942665826396677e"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("*137 characters (exactly block + 1 size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136 + 1), '*'); // size of block
			return cthash::keccak_384().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "8c7e02a3f295c4117b03d7f5cc58ca1350d493053e1e9a1817a7cc12be29548f9321bd6ca7dca87a244464bf3e005ed4"_keccak_384);
		REQUIRE(r0 == r1);
	}

	SECTION("*2500 characters") {
		auto in = std::string(size_t(2500), '*'); // size of block + 1
		const auto r0 = cthash::keccak_384().update(in).final();
		REQUIRE(r0 == "5cf7bab34903785ab0dce2eb4497ac80dc0601816ed5fd0147f0eb3fc93930186f32b6762c2e507e2e8856c87678fa0f"_keccak_384);
	}

	SECTION("*2500 by one") {
		auto h = cthash::keccak_384();
		for (int i = 0; i != 2500; ++i) {
			h.update("*");
		}
		const auto r0 = h.final();
		REQUIRE(r0 == "5cf7bab34903785ab0dce2eb4497ac80dc0601816ed5fd0147f0eb3fc93930186f32b6762c2e507e2e8856c87678fa0f"_keccak_384);
	}
}

TEST_CASE("keccak-384 stability") {
	auto h = cthash::keccak_384();

	constexpr int end = int(h.rate) * 2;

	for (int i = 0; i != end; ++i) {
		const auto piece = std::string(size_t(i), '#');
		h.update(piece);
	}

	const auto r0 = h.final();
	REQUIRE(r0 == "52532d103f21bd143314e7b5b1bd7a79ebfc3c8e56e2689ee6527523a4c26baeee3065775163f43148e08aeefd302889"_keccak_384);
}

TEST_CASE("keccak-384 printing") {
	auto hash = cthash::keccak_384().final();
	std::ostringstream ss;
	ss << hash;

	REQUIRE(ss.str() == "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
}

TEST_CASE("keccak-384 formatting") {
	auto hash = cthash::keccak_384().final();
	auto str = std::format("{}", hash);

	REQUIRE(str == "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
}

TEST_CASE("keccak-384 formatting (hexdec explicitly)") {
	auto hash = cthash::keccak_384().final();
	auto str = std::format("{:hexdec}", hash);

	REQUIRE(str == "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
}

TEST_CASE("keccak-384 formatting (z_base32 explicitly)") {
	auto hash = cthash::keccak_384().final();
	auto str = std::format("{:zbase32}", hash);

	REQUIRE(str == "fotte4udwkpc9gx88qrxto1qij6hcni8qfhy3uyypm79id9ne6p15wi1nptdg7nbiojmkfctdfm96");
}

TEST_CASE("keccak-384 formatting (base64url explicitly)") {
	auto hash = cthash::keccak_384().update("hanicka").final();
	auto str = std::format("{:base64url}", hash);

	REQUIRE(str == "v01lOGx-qbapXws1rPgevBZm5wRw1ujjNDBzIHr2P_fiEk1uIWpnes1lC7T0SwH-");
}

TEST_CASE("keccak-384 formatting (binary explicitly)") {
	auto hash = cthash::keccak_384().update("hanicka").final();
	auto str = std::format("{:binary}", hash);

	REQUIRE(str ==
		"1011111101001101011001010011100001101100011111101010100110110110101010010101"
		"1111000010110011010110101100111110000001111010111100000101100110011011100111"
		"0000010001110000110101101110100011100011001101000011000001110011001000000111"
		"1010111101100011111111110111111000100001001001001101011011100010000101101010"
		"0110011101111010110011010110010100001011101101001111010001001011000000011111"
		"1110");
}

template <typename Container = std::string> auto materialize(auto && range) {
	auto result = Container{};
	result.resize(range.size());
	auto [in, out] = std::ranges::copy(range, result.begin());
	REQUIRE(in == range.end());
	REQUIRE(out == result.end());
	return result;
}

TEST_CASE("static and dynamic path generates same results (keccak384)") {
	auto hash = cthash::keccak_384().update("hanicka").final();

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

TEST_CASE("keccak-384 formatting (shortening)") {
	auto hash = cthash::keccak_384().final();
	auto str = std::format("{:hexdec}..{:hexdec}", hash.prefix<3>(), hash.suffix<3>());

	REQUIRE(str == "2c2314..1957ff");
}
