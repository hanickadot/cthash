#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/encodings.hpp>
#include <sstream>

using namespace std::string_view_literals;

template <typename> struct identify;

template <typename E> bool match_encoding(E, std::string_view expected) {
	return cthash::match_encoding<E>(expected);
}

TEST_CASE("select hexdec encoding") {
	const auto enc_default = cthash::select_runtime_encoding(""sv).encoding;
	enc_default.visit([]<typename E>(E e) {
		INFO(E::name);
		REQUIRE(match_encoding(e, "base16"));
	});

	const auto enc1 = cthash::select_runtime_encoding("hexdec"sv).encoding;
	enc1.visit([]<typename E>(E e) {
		REQUIRE(match_encoding(e, "hexdec"));
	});

	const auto enc2 = cthash::select_runtime_encoding("base64"sv).encoding;
	enc2.visit([]<typename E>(E e) {
		INFO(E::name);
		REQUIRE(match_encoding(e, "base64"));
	});

	const auto enc3 = cthash::select_runtime_encoding("base64_no_padding"sv).encoding;
	enc3.visit([]<typename E>(E e) {
		INFO(E::name);
		REQUIRE(match_encoding(e, "base64_no_padding"));
	});

	REQUIRE_THROWS_AS(cthash::select_runtime_encoding("unexisting"sv), std::invalid_argument);
}
