#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/base.hpp>
#include <sstream>

using namespace std::string_view_literals;

template <typename CharT = char> static auto materialize(const auto & range) {
	std::basic_string<CharT> output;
	for (CharT c: range) {
		output += c;
	}

	// copy from range
	std::basic_string<CharT> output2;
	output2.resize(range.size());
	auto it = output2.begin();
	const auto end = output2.end();
	const auto [in, out] = std::ranges::copy(range.begin(), range.end(), it);

	REQUIRE(out == end);
	REQUIRE(in == range.end());
	REQUIRE(output.size() == output2.size());
	REQUIRE(range.size() == output2.size());

	// stream support
	std::basic_stringstream<CharT> stream3;
	stream3 << range;
	const auto output3 = std::move(stream3).str();
	REQUIRE(output2.size() == output3.size());
	REQUIRE(output.size() == output3.size());

	// ranges::to
	const auto output4 = range | std::ranges::to<std::basic_string>();

	return output2;
}

static auto result_size(const auto & range) {
	return range.size();
}

template <typename ValueT, typename... Args> auto build_array(Args... args) {
	return std::array<ValueT, sizeof...(args)>{static_cast<ValueT>(args)...};
}

TEST_CASE("lazy base64 basics") {
	const auto view1 = "Man"sv | cthash::encode<cthash::base64>;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::encode<cthash::base64>;
	REQUIRE(materialize(view2) == "TWE=");

	const auto view3 = "M"sv | cthash::encode<cthash::base64>;
	REQUIRE(materialize(view3) == "TQ==");

	const auto empty = ""sv | cthash::encode<cthash::base64>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("bytes to base64") {
	const auto bytes = build_array<std::byte>('M', 'a', 'n');
	const auto view1 = std::span(bytes) | cthash::encode<cthash::base64>;

	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = std::span(bytes).first(2) | cthash::encode<cthash::base64>;
	REQUIRE(materialize(view2) == "TWE=");

	const auto view3 = std::span(bytes).first(1) | cthash::encode<cthash::base64>;
	REQUIRE(materialize(view3) == "TQ==");

	const auto empty = std::span(bytes).first(0) | cthash::encode<cthash::base64>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy base64 without padding basics") {
	const auto view1 = "Man"sv | cthash::encode<cthash::base64_no_padding>;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::encode<cthash::base64_no_padding>;
	REQUIRE(materialize(view2) == "TWE");

	const auto view3 = "M"sv | cthash::encode<cthash::base64_no_padding>;
	REQUIRE(materialize(view3) == "TQ");

	const auto empty = ""sv | cthash::encode<cthash::base64_no_padding>;
	REQUIRE(materialize(empty) == "");
}

template <typename T> constexpr auto make_array(std::convertible_to<T> auto... values) {
	return std::array<T, sizeof...(values)>{static_cast<T>(values)...};
}

TEST_CASE("lazy base64 value corner-cases") {
	const auto arr = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF);
	const auto view1 = arr | cthash::encode<cthash::base64>;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A/wD/");
}

TEST_CASE("lazy base64url value corner-cases") {
	const auto arr = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF);
	const auto view1 = arr | cthash::encode<cthash::base64url>;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A_wD_");
}

TEST_CASE("lazy base64 value corner-cases (construct from temporary)") {
	const auto view1 = make_array<unsigned char>(0, 0xFFu, 0, 0xFF, 0, 0xFF) | cthash::encode<cthash::base64>;
	static_assert(std::input_iterator<decltype(view1.begin())>);
	static_assert(std::ranges::input_range<decltype(view1)>);
	REQUIRE(materialize(view1) == "AP8A/wD/");
}

TEST_CASE("lazy base64url basics") {
	const auto view1 = "Man"sv | cthash::encode<cthash::base64url>;
	REQUIRE(materialize(view1) == "TWFu");

	const auto view2 = "Ma"sv | cthash::encode<cthash::base64url>;
	REQUIRE(materialize(view2) == "TWE");

	const auto view3 = "M"sv | cthash::encode<cthash::base64url>;
	REQUIRE(materialize(view3) == "TQ");

	const auto view4 = "ab~"sv | cthash::encode<cthash::base64url>;
	REQUIRE(materialize(view4) == "YWJ-");

	const auto empty = ""sv | cthash::encode<cthash::base64url>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy base32 basics") {
	const auto view1 = "abcde"sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(view1) == "MFRGGZDF");

	const auto view2 = "abcd"sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(view2) == "MFRGGZA=");

	const auto view3 = "abc"sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(view3) == "MFRGG===");

	const auto view4 = "ab"sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(view4) == "MFRA====");

	const auto view5 = "a"sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(view5) == "ME======");

	const auto empty = ""sv | cthash::encode<cthash::base32>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy z-base32 basics") {
	const auto view1 = "abcde"sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(view1) == "cftgg3df");

	const auto view2 = "abcd"sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(view2) == "cftgg3y");

	const auto view3 = "abc"sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(view3) == "cftgg");

	const auto view4 = "ab"sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(view4) == "cfty");

	const auto view5 = "a"sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(view5) == "cr");

	const auto empty = ""sv | cthash::encode<cthash::z_base32>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy hexdec basics") {
	const auto view1 = "Aloha"sv | cthash::encode<cthash::hexdec>;
	REQUIRE(materialize(view1) ==
		"41"
		"6c"
		"6f"
		"68"
		"61");

	const auto empty = ""sv | cthash::encode<cthash::hexdec>;
	REQUIRE(materialize(empty) == "");
}

TEST_CASE("lazy binary basics") {
	const auto view1 = "Aloha"sv | cthash::encode<cthash::binary>;
	REQUIRE(materialize(view1) ==
		"01000001"
		"01101100"
		"01101111"
		"01101000"
		"01100001");

	const auto empty = ""sv | cthash::encode<cthash::binary>;
	REQUIRE(materialize(empty) == "");
}
