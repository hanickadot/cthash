#include <cthash/xxhash.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("xxhash basics", "[xxh]") {
	SECTION("empty string") {
		const std::string_view empty = "";

		REQUIRE(cthash::xxhash<32>(empty, 0u) == 0x02cc5d05u);
		REQUIRE(cthash::xxhash<64>(empty, 0u) == 0xef46db3751d8e999ull);

		REQUIRE(cthash::xxhash<32>(empty, 42u) == 0xd5be6eb8);
		REQUIRE(cthash::xxhash<64>(empty, 42u) == 0x98b1582b0977e704ull);
	}

	SECTION("empty string") {
		const std::string_view in = "hello there";

		REQUIRE(cthash::xxhash<32>(in, 0u) == 0x371c3e72u);
		REQUIRE(cthash::xxhash<64>(in, 0u) == 0x08f296af889a203cull);

		REQUIRE(cthash::xxhash<32>(in, 42u) == 0x4a90b3c2u);
		REQUIRE(cthash::xxhash<64>(in, 42u) == 0x1a910e9618a06c28ull);
	}

	SECTION("longer string") {
		const std::string_view in = "hello there, from somehow long string! really this should be enought :)";

		REQUIRE(cthash::xxhash<32>(in, 0u) == 0x2daeaacdu);
		REQUIRE(cthash::xxhash<64>(in, 0u) == 0x4f6f14232e5ab579ull);

		REQUIRE(cthash::xxhash<32>(in, 42u) == 0xb66e8e53u);
		REQUIRE(cthash::xxhash<64>(in, 42u) == 0x62eee52b8dbf7af9ull);
	}

	SECTION("longer string") {
		const std::string_view lit = "hello there, from somehow long string! really this should be enought :)";

		std::string in;

		in.reserve(lit.size() * 1000u);

		for (int i = 0; i != 1000; ++i) {
			in.append(std::data(lit), std::size(lit));
		}

		REQUIRE(cthash::xxhash<32>(std::string_view(in), 0u) == 0xa7d7a81du);
		REQUIRE(cthash::xxhash<64>(std::string_view(in), 0u) == 0xbd6f22acc408272dull);
	}
}

TEST_CASE("xxhash benchmarks", "[xxh]") {
	auto val = std::string(10u * 1024u * 1024u, '*');

	BENCHMARK("really long string (32bit) (10MB)") {
		return cthash::xxhash<32>(std::string_view(val));
	};

	BENCHMARK("really long string (64bit) (10MB)") {
		return cthash::xxhash<64>(std::string_view(val));
	};

	auto val2 = std::string(1024u * 1024u * 1024u, '*');

	BENCHMARK("really long string (32bit) (1GB)") {
		return cthash::xxhash<32>(std::string_view(val2));
	};

	BENCHMARK("really long string (64bit) (1GB)") {
		return cthash::xxhash<64>(std::string_view(val2));
	};
}