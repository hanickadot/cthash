#include <cthash/sha2.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace cthash::literals;

template <size_t N> consteval auto array_of_zero_bytes() {
	std::array<std::byte, N> output;
	for (std::byte & val: output) val = std::byte{0};
	return output;
}

TEST_CASE("sha256 basics") {
	constexpr auto v1 = cthash::sha256{}.update("").final();
	REQUIRE(v1 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"_sha256);

	constexpr auto v2 = cthash::sha256{}.update("hana").final();
	REQUIRE(v2 == "599ba25a0d7c7d671bee93172ca7e272fc87f0c0e02e44df9e9436819067ea28"_sha256);

	constexpr auto v3 = cthash::sha256{}.update(array_of_zero_bytes<96>()).final();
	REQUIRE(v3 == "2ea9ab9198d1638007400cd2c3bef1cc745b864b76011a0e1bc52180ac6452d4"_sha256);

	constexpr auto v4 = cthash::sha256{}.update(array_of_zero_bytes<120>()).final();
	REQUIRE(v4 == "6edd9f6f9cc92cded36e6c4a580933f9c9f1b90562b46903b806f21902a1a54f"_sha256);

	constexpr auto v5 = cthash::sha256{}.update(array_of_zero_bytes<128>()).final();
	REQUIRE(v5 == "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca"_sha256);
}

TEST_CASE("sha256 measurements") {
	std::array<std::byte, 128> input{};

	for (int i = 0; i != (int)input.size(); ++i) {
		input[i] = static_cast<std::byte>(i);
	}

	BENCHMARK("16 byte input") {
		return cthash::sha256{}.update(std::span(input).first(16)).final();
	};

	BENCHMARK("32 byte input") {
		return cthash::sha256{}.update(std::span(input).first(32)).final();
	};

	BENCHMARK("48 byte input") {
		return cthash::sha256{}.update(std::span(input).first(48)).final();
	};

	BENCHMARK("64 byte input") {
		return cthash::sha256{}.update(std::span(input).first(64)).final();
	};

	BENCHMARK("96 byte input") {
		return cthash::sha256{}.update(std::span(input).first(96)).final();
	};
}

TEST_CASE("sha256 long hash over 512MB", "[.long]") {
	cthash::sha256 h{};
	for (int i = 0; i != 512 * 1024; ++i) {
		h.update(array_of_zero_bytes<1024>());
	}
	REQUIRE(h.size() == 512u * 1024u * 1024u);
	const auto r = h.final();
	const auto end = std::chrono::high_resolution_clock::now();

	REQUIRE(r == "9acca8e8c22201155389f65abbf6bc9723edc7384ead80503839f49dcc56d767"_sha256);
}
