#include <catch2/catch_test_macros.hpp>
#include "../internal/support.hpp"
#include <cthash/sha3/keccak.hpp>
#include <iostream>

using namespace cthash::literals;

TEST_CASE("keccak-512 basics") {
	const auto a = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"_keccak_512;
	REQUIRE(a.size() == 512u / 8u);
}

TEST_CASE("keccak-512 test strings") {
	SECTION("empty") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("empty with bytes") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update(std::span<const std::byte>()).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"_keccak_512);
		REQUIRE(r0 == r1);
	}
	SECTION("one letter") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("a").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "9c46dbec5d03f74352cc4a4da354b4e9796887eeb66ac292617692e765dbe400352559b16229f97b27614b51dbfbbb14613f2c10350435a8feaf53f73ba01c7c"_keccak_512);
		REQUIRE(r0 == r1);
	}
	SECTION("two letters") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("ab").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "b4828cc4e3fe9e5bc17013579be02b2a900c7afd7084c1f29450fcb267dcf1bc4def62a2cbefda507735547c203a3699f8a0d972fd13139dd73af0a3c30501e7"_keccak_512);
		REQUIRE(r0 == r1);
	}
	SECTION("test") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("test").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e"_keccak_512);
		REQUIRE(r0 == r1);
	}
	SECTION("experiment") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("experiment").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "b4b480639fdd156014226bd64471df71658e66821b30c14b257ebc6fe921c50fb870eeff0b9eb4c6849e5deb129a68bca6ac847116da789231a7dc32fae4f14b"_keccak_512);
		REQUIRE(r0 == r1);
	}
	SECTION("ethereum") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("Hello, Ethereum!").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "17081fdd12b66dce0adabc0b44d7c29b75670b5630437d1fc57df3dda6b85200c2e691f9480f3ed85b1d415ec638efa77529de36e24d77b5987bced369b752be"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("hello world") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("Hello, world! Keccak-512 Hash").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "94c3f40f39347cc633814f9391cdcfe0536a232458f8015d2189b08b69466fee7480bf1cfc8479a834edf84c06b1f02f8440681bfefeb3faf6c59b75002717ad"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("hanicka") {
		constexpr auto calculation = []() {
			return cthash::keccak_512().update("hanicka").final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "0900ff64ae4960c1c157a026ecbfd22c96cfdc3bb3a68092b73e2e893d32c95623eb3a7a5f9e03264296c55684dcc0276795a92fa4e2e40432b2b5d822ff999b"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("*136 characters (exactly block size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136), '*'); // size of block
			return cthash::keccak_512().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "85684d78ee7b7833d89e3eed902fed74eabebe02e0880e842f03d47576330a3b0d699129d0d33f0f60d31cd5f10c8ecf806b466ded8e611843cefd05b07fa1c6"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("*137 characters (exactly block + 1 size)") {
		constexpr auto calculation = []() {
			auto in = std::string(size_t(136 + 1), '*'); // size of block
			return cthash::keccak_512().update(in).final();
		};

		auto r0 = calculation();
		constexpr auto r1 = calculation();

		REQUIRE(r0 == "d8e0a98d46aaf3d9911c929d7be6bfa6c897009a296533fbc6083fb7302e2f6ad35a5117dcdf59645f9efca9a2e2241c71e7c5f115b94044a21e3715b4534c10"_keccak_512);
		REQUIRE(r0 == r1);
	}

	SECTION("*2500 characters") {
		auto in = std::string(size_t(2500), '*'); // size of block + 1
		const auto r0 = cthash::keccak_512().update(in).final();
		REQUIRE(r0 == "1bcec0f93dd40948c8b2eceeb48a2b39dae57e8ea9150da3273708204e2e6e27a680c9e559e46ff6ce3649d96f949e03389cdd5eff65a74346996d48b2eb4d91"_keccak_512);
	}

	SECTION("*2500 by one") {
		auto h = cthash::keccak_512();
		for (int i = 0; i != 2500; ++i) {
			h.update("*");
		}
		const auto r0 = h.final();
		REQUIRE(r0 == "1bcec0f93dd40948c8b2eceeb48a2b39dae57e8ea9150da3273708204e2e6e27a680c9e559e46ff6ce3649d96f949e03389cdd5eff65a74346996d48b2eb4d91"_keccak_512);
	}
}

TEST_CASE("keccak-512 stability") {
	auto h = cthash::keccak_512();

	constexpr int end = int(h.rate) * 2;

	for (int i = 0; i != end; ++i) {
		const auto piece = std::string(size_t(i), '#');
		h.update(piece);
	}

	const auto r0 = h.final();
	REQUIRE(r0 == "5e5d103f89e8d19a870fa4d495593ba5fa270db723c611d05c1ffc70c717a236fd18614b69c93f2773e4361843c5bd06c153b2229ed9120506cab4339643a7bd"_keccak_512);
}

TEST_CASE("keccak-512 printing") {
	auto hash = cthash::keccak_512().final();
	std::ostringstream ss;
	ss << hash;

	REQUIRE(ss.str() == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
}

TEST_CASE("keccak-512 formatting") {
	auto hash = cthash::keccak_512().final();
	auto str = std::format("{}", hash);

	REQUIRE(str == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
}

TEST_CASE("keccak-512 formatting (hexdec explicitly)") {
	auto hash = cthash::keccak_512().final();
	auto str = std::format("{:hexdec}", hash);

	REQUIRE(str == "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
}

TEST_CASE("keccak-512 formatting (z_base32 explicitly)") {
	auto hash = cthash::keccak_512().final();
	auto str = std::format("{:zbase32}", hash);

	REQUIRE(str == "b4iwfz1c8ui3rpxh1gsx934gskqnukgdc45hcd1qc9ngph5kecncyd7j3mh7o6mszjdjz19ychj5epxo18z1q4x5nagpic37g3agodo");
}

TEST_CASE("keccak-512 formatting (base64url explicitly)") {
	auto hash = cthash::keccak_512().update("hanicka").final();
	auto str = std::format("{:base64url}", hash);

	REQUIRE(str == "CQD_ZK5JYMHBV6Am7L_SLJbP3DuzpoCStz4uiT0yyVYj6zp6X54DJkKWxVaE3MAnZ5WpL6Ti5AQysrXYIv-Zmw");
}

TEST_CASE("keccak-512 formatting (binary explicitly)") {
	auto hash = cthash::keccak_512().update("hanicka").final();
	auto str = std::format("{:binary}", hash);

	REQUIRE(str ==
		"0000100100000000111111110110010010101110010010010110000011000001110000010101"
		"0111101000000010011011101100101111111101001000101100100101101100111111011100"
		"0011101110110011101001101000000010010010101101110011111000101110100010010011"
		"1101001100101100100101010110001000111110101100111010011110100101111110011110"
		"0000001100100110010000101001011011000101010101101000010011011100110000000010"
		"0111011001111001010110101001001011111010010011100010111001000000010000110010"
		"10110010101101011101100000100010111111111001100110011011");
}

template <typename Container = std::string> auto materialize(auto && range) {
	auto result = Container{};
	result.resize(range.size());
	auto [in, out] = std::ranges::copy(range, result.begin());
	REQUIRE(in == range.end());
	REQUIRE(out == result.end());
	return result;
}

TEST_CASE("static and dynamic path generates same results (keccak512)") {
	auto hash = cthash::keccak_512().update("hanicka").final();

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

TEST_CASE("keccak-512 formatting (shortening)") {
	auto hash = cthash::keccak_512().final();
	auto str = std::format("{:hexdec}..{:hexdec}", hash.prefix<3>(), hash.suffix<3>());

	REQUIRE(str == "0eab42..70680e");
}
