#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/base.hpp>
#include <cthash/value.hpp>
#include <sstream>

using namespace std::string_view_literals;
using namespace cthash::literals;

static auto materialize(const auto & range, std::optional<size_t> expected_size = std::nullopt) {
	return range | std::ranges::to<std::string>();
}

TEST_CASE("decode hexdec") {
	const auto view0 = ""sv | cthash::decode(cthash::base16);
	REQUIRE(view0.size() == 0);
	REQUIRE(materialize(view0) == "");

	const auto view1 = "00000000"sv | cthash::decode(cthash::base16);
	REQUIRE(view1.size() == 4);
	REQUIRE(materialize(view1) == "\0\0\0\0"sv);

	const auto view2 = "3432"sv | cthash::decode(cthash::base16);
	REQUIRE(view2.size() == 2);
	REQUIRE(materialize(view2) == "42");

	const auto view3 = "48616E61"sv | cthash::decode(cthash::base16);
	REQUIRE(view3.size() == 4);
	REQUIRE(materialize(view3) == "Hana");

	const auto view4 = "48616e61"sv | cthash::decode(cthash::base16);
	REQUIRE(view4.size() == 4);
	REQUIRE(materialize(view4) == "Hana");
}

TEST_CASE("decode base64") {
	const auto view0 = ""sv | cthash::decode(cthash::base64);
	REQUIRE(view0.size() == 0);
	REQUIRE(materialize(view0) == "");

	const auto view1 = "aGVsbG8gdGhlcmU="sv | cthash::decode(cthash::base64);
	REQUIRE(view1.size() == 11u);
	REQUIRE(materialize(view1) == "hello there"sv);
	REQUIRE(materialize(view1).size() == 11u);

	const auto view2 = "YmFuYW5h"sv | cthash::decode(cthash::base64);
	REQUIRE(view2.size() == 6u);
	REQUIRE(materialize(view2) == "banana"sv);
}

TEST_CASE("decode binary") {
	const auto view0 = ""sv | cthash::decode(cthash::binary);
	REQUIRE(view0.size() == 0);
	REQUIRE(materialize(view0) == "");

	const auto view1 = "00000000"sv | cthash::decode(cthash::binary);
	REQUIRE(view1.size() == 1u);
	REQUIRE(materialize(view1) == "\0"sv);
	REQUIRE(materialize(view1).size() == 1u);
}

template <auto Encoding> auto roundtrip(const std::vector<uint8_t> & provided, std::optional<std::string_view> expected_encoded = std::nullopt) {
	const auto encoded = provided | cthash::encode(Encoding) | std::ranges::to<std::string>();
	if (expected_encoded.has_value()) {
		// check fi we provided how it should encoded
		REQUIRE(encoded == *expected_encoded);
	}

	const auto decode_view = encoded | cthash::decode(Encoding);

	SECTION("should give same size as provided.size()") {
		// should give same size as provided size
		REQUIRE(decode_view.size() == provided.size());
	}

	const auto decoded = decode_view | std::ranges::to<std::vector<uint8_t>>();

	SECTION("decode_view after materializing should be same as provided") {
		REQUIRE(provided.size() == decoded.size());
		REQUIRE(provided == decoded);
	}

	const auto encoded2 = decoded | cthash::encode(Encoding) | std::ranges::to<std::string>();

	SECTION("subsequent encoding should be same as first encoding") {
		REQUIRE(encoded2 == encoded);
	}
}

TEMPLATE_TEST_CASE("decode roundtrip", "[roundtrip]", cthash::encoding::binary, cthash::encoding::octal, cthash::encoding::octal_no_padding, cthash::encoding::hexdec, cthash::encoding::base32, cthash::encoding::base64) {
	static constexpr auto encoding = TestType{};

	SECTION("empty") {
		const auto provided = std::vector<uint8_t>{};
		roundtrip<encoding>(provided);
	}
	SECTION("one byte") {
		const auto provided = std::vector<uint8_t>{0x1u};
		roundtrip<encoding>(provided);
	}
	SECTION("two bytes") {
		const auto provided = std::vector<uint8_t>{0x1u, 0xFFu};
		roundtrip<encoding>(provided);
	}
	SECTION("three bytes") {
		const auto provided = std::vector<uint8_t>{0x1u, 0xFFu, 0x42u};
		roundtrip<encoding>(provided);
	}
	SECTION("four bytes") {
		const auto provided = std::vector<uint8_t>{0x1u, 0xFFu, 0x42u, 0x16u};
		roundtrip<encoding>(provided);
	}
	SECTION("five bytes") {
		const auto provided = std::vector<uint8_t>{0x1u, 0xFFu, 0x42u, 0x16u, 011u};
		roundtrip<encoding>(provided);
	}
}