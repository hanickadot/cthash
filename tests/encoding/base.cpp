#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/base.hpp>
#include <sstream>

using namespace std::string_view_literals;

static auto materialize(const auto & range) {
	using char_type = std::ranges::range_value_t<decltype(range)>;
	std::basic_string<char_type> output;
	for (char_type c: range) {
		output += c;
	}

	std::basic_string<char_type> output2;
	output2.resize(range.size());
	auto it = output2.begin();
	const auto end = output2.end();
	const auto [in, out] = std::ranges::copy(range.begin(), range.end(), it);

	REQUIRE(out == end);
	REQUIRE(in == range.end());
	REQUIRE(output.size() == output2.size());
	REQUIRE(range.size() == output2.size());

	return output2;
}

static auto result_size(const auto & range) {
	return range.size();
}

template <typename ValueT, typename... Args> auto build_array(Args... args) {
	return std::array<ValueT, sizeof...(args)>{static_cast<ValueT>(args)...};
}

TEST_CASE("lazy base64 basics") {
	const auto view1 = "Man"sv | cthash::base64_encode;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::base64_encode;
	REQUIRE(materialize(view2) == "TWE=");

	const auto view3 = "M"sv | cthash::base64_encode;
	REQUIRE(materialize(view3) == "TQ==");

	const auto empty = ""sv | cthash::base64_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("bytes to base64") {
	const auto bytes = build_array<std::byte>('M', 'a', 'n');
	const auto view1 = std::span(bytes) | cthash::base64_encode;

	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = std::span(bytes).first(2) | cthash::base64_encode;
	REQUIRE(materialize(view2) == "TWE=");

	const auto view3 = std::span(bytes).first(1) | cthash::base64_encode;
	REQUIRE(materialize(view3) == "TQ==");

	const auto empty = std::span(bytes).first(0) | cthash::base64_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy base64 without padding basics") {
	const auto view1 = "Man"sv | cthash::base64_no_padding_encode;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::base64_no_padding_encode;
	REQUIRE(materialize(view2) == "TWE");

	const auto view3 = "M"sv | cthash::base64_no_padding_encode;
	REQUIRE(materialize(view3) == "TQ");

	const auto empty = ""sv | cthash::base64_no_padding_encode;
	REQUIRE(materialize(empty) == "");
}

template <typename T> constexpr auto make_array(std::convertible_to<T> auto... values) {
	return std::array<T, sizeof...(values)>{static_cast<T>(values)...};
}

TEST_CASE("lazy base64 value corner-cases") {
	const auto arr = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF);
	const auto view1 = arr | cthash::base64_encode;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A/wD/");
}

TEST_CASE("lazy base64url value corner-cases") {
	const auto arr = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF);
	const auto view1 = arr | cthash::base64url_encode;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A_wD_");
}

TEST_CASE("lazy base64 value corner-cases (construct from temporary)") {
	const auto view1 = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF) | cthash::base64_encode;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A/wD/");
}

TEST_CASE("lazy base64url basics") {
	const auto view1 = "Man"sv | cthash::base64url_encode;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::base64url_encode;
	REQUIRE(materialize(view2) == "TWE");

	const auto view3 = "M"sv | cthash::base64url_encode;
	REQUIRE(materialize(view3) == "TQ");

	const auto view4 = "ab~"sv | cthash::base64url_encode;
	REQUIRE(materialize(view4) == "YWJ-");

	const auto empty = ""sv | cthash::base64url_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy base32 basics") {
	const auto view1 = "abcde"sv | cthash::base32_encode;
	REQUIRE(materialize(view1) == "MFRGGZDF");

	const auto view2 = "abcd"sv | cthash::base32_encode;
	REQUIRE(materialize(view2) == "MFRGGZA=");

	const auto view3 = "abc"sv | cthash::base32_encode;
	REQUIRE(materialize(view3) == "MFRGG===");

	const auto view4 = "ab"sv | cthash::base32_encode;
	REQUIRE(materialize(view4) == "MFRA====");

	const auto view5 = "a"sv | cthash::base32_encode;
	REQUIRE(materialize(view5) == "ME======");

	const auto empty = ""sv | cthash::base32_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy z-base32 basics") {
	const auto view1 = "abcde"sv | cthash::z_base32_encode;
	REQUIRE(materialize(view1) == "cftgg3df");

	const auto view2 = "abcd"sv | cthash::z_base32_encode;
	REQUIRE(materialize(view2) == "cftgg3y");

	const auto view3 = "abc"sv | cthash::z_base32_encode;
	REQUIRE(materialize(view3) == "cftgg");

	const auto view4 = "ab"sv | cthash::z_base32_encode;
	REQUIRE(materialize(view4) == "cfty");

	const auto view5 = "a"sv | cthash::z_base32_encode;
	REQUIRE(materialize(view5) == "cr");

	const auto empty = ""sv | cthash::z_base32_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy hexdec basics") {
	const auto view1 = "Aloha"sv | cthash::hexdec_encode;
	REQUIRE(materialize(view1) ==
		"41"
		"6c"
		"6f"
		"68"
		"61");

	const auto empty = ""sv | cthash::hexdec_encode;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy binary basics") {
	const auto view1 = "Aloha"sv | cthash::binary_encode;
	REQUIRE(materialize(view1) ==
		"01000001"
		"01101100"
		"01101111"
		"01101000"
		"01100001");

	const auto empty = ""sv | cthash::binary_encode;
	REQUIRE(materialize(empty) == "");
}
