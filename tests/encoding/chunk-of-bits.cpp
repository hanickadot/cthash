#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/chunk-of-bits.hpp>
#include <sstream>

using namespace std::string_view_literals;

auto convert_to_vector(auto && range) {
	std::vector<std::ranges::range_value_t<std::remove_cvref_t<decltype(range)>>> output{};

	for (auto && value: range) {
		output.emplace_back(value);
	}

	return output;
}

template <typename...> struct identify;

TEST_CASE("construction from a reference") {
	auto x = std::array<uint8_t, 4>{1, 2, 3, 4};
	auto v = x | cthash::chunk_of_bits<4>;
	REQUIRE(v.size() == 8);
}

TEST_CASE("construction from a const reference") {
	const auto x = std::array<uint8_t, 4>{1, 2, 3, 4};
	auto v = x | cthash::chunk_of_bits<4>;
	REQUIRE(v.size() == 8);
}

TEST_CASE("construction from a temporary") {
	auto v = std::array<uint8_t, 4>{1, 2, 3, 4} | cthash::chunk_of_bits<4>;
	REQUIRE(v.size() == 8);
}

TEST_CASE("construction of chunk view (8bit => 4bit)") {
	const auto v = "aloha"sv | cthash::chunk_of_bits<4>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	REQUIRE(result.size() == 10u);

	REQUIRE(result[0].value == 0x6);
	REQUIRE(result[1].value == 0x1);

	REQUIRE(result[2].value == 0x6);
	REQUIRE(result[3].value == 0xC);

	REQUIRE(result[4].value == 0x6);
	REQUIRE(result[5].value == 0xF);

	REQUIRE(result[6].value == 0x6);
	REQUIRE(result[7].value == 0x8);

	REQUIRE(result[8].value == 0x6);
	REQUIRE(result[9].value == 0x1);
}

TEST_CASE("construction of chunk view (8bit => 6bit)") {
	const auto v = "Man"sv | cthash::chunk_of_bits<6>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	REQUIRE(result.size() == 4u);

	REQUIRE(result[0].value == 0b010011u);
	REQUIRE(result[1].value == 0b010110u);
	REQUIRE(result[2].value == 0b000101u);
	REQUIRE(result[3].value == 0b101110u);
}

TEST_CASE("construction of chunk view (8bit => 6bit, unaligned, without padding)") {
	const auto v = "Ma"sv | cthash::chunk_of_bits<6, false>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	auto it = result.begin();
	const auto end = result.end();

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010011u);
	REQUIRE(it->missing_bits == 0u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010110u);
	REQUIRE(it->missing_bits == 0u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b000100u);
	REQUIRE(it->missing_bits == 2u);
	++it;

	REQUIRE(it == end);
}

TEST_CASE("construction of chunk view (8bit => 6bit, unaligned, with padding)") {
	const auto v = "Ma"sv | cthash::chunk_of_bits<6, true>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	auto it = result.begin();
	const auto end = result.end();

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010011u);
	REQUIRE(it->missing_bits == 0u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010110u);
	REQUIRE(it->missing_bits == 0u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b000100u);
	REQUIRE(it->missing_bits == 2u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b000000u);
	// REQUIRE(it->missing_bits == 6u);
	// REQUIRE(it->is_padding());
	++it;

	REQUIRE(it == end);
}

TEST_CASE("construction of chunk view (8bit => 6bit, unaligned, with padding, second)") {
	const auto v = "M"sv | cthash::chunk_of_bits<6, true>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	auto it = result.begin();
	const auto end = result.end();

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010011u);
	REQUIRE(it->missing_bits == 0u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b010000u);
	REQUIRE(it->missing_bits == 4u);
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b000000u);
	// REQUIRE(it->missing_bits == 6u);
	// REQUIRE(it->is_padding());
	++it;

	REQUIRE(it != end);
	REQUIRE(it->value == 0b000000u);
	// REQUIRE(it->missing_bits == 6u);
	// REQUIRE(it->is_padding());
	++it;

	REQUIRE(it == end);
}

TEST_CASE("construction of chunk view (8bit => 6bit, unaligned, with padding, empty)") {
	const auto v = ""sv | cthash::chunk_of_bits<6, true>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	auto it = result.begin();
	const auto end = result.end();

	REQUIRE(it == end);
}

TEST_CASE("construction of chunk view (8bit => 1bit)") {
	auto arr = std::array<unsigned char, 1>{0xF8};
	const auto v = arr | cthash::chunk_of_bits<1>;

	static_assert(std::input_iterator<std::remove_cvref_t<decltype(v.begin())>>);
	static_assert(std::ranges::input_range<std::remove_cvref_t<decltype(v)>>);

	const auto result = convert_to_vector(v);

	REQUIRE(result.size() == 8u);

	REQUIRE(result[0].value == 0b1);
	REQUIRE(result[1].value == 0b1);
	REQUIRE(result[2].value == 0b1);
	REQUIRE(result[3].value == 0b1);
	REQUIRE(result[4].value == 0b1);
	REQUIRE(result[5].value == 0b0);
	REQUIRE(result[6].value == 0b0);
	REQUIRE(result[7].value == 0b0);
}