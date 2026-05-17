#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cthash/cthash.hpp>
#include <sstream>

using namespace std::string_view_literals;
using namespace cthash::literals;

template <typename> struct identify;

constexpr std::string stringify(auto && range) {
	return std::ranges::to<std::string>(range);
}

TEST_CASE("in and out sha256") {
	// read from somewhere already calculated
	auto hash = cthash::sha256_value{cthash::base64, "AgapeEOxuk+7FH1HJVDsO17oqsrfNwdSIVckCUDRvr0="sv};

	// calculating from
	auto chash = cthash::sha256("aloha").final();
	REQUIRE(hash == chash);

	// literal
	auto phash = "0206a97843b1ba4fbb147d472550ec3b5ee8aacadf3707522157240940d1bebd"_sha256;
	REQUIRE(phash == chash);
	REQUIRE(phash == hash);

	// and encode into base32 (lazily, hence the helper)
	auto ohash = stringify(hash | cthash::encode(cthash::z_base32));
	REQUIRE(ohash == "yedk16ndsg7r9qawxid1kw8c8pxqtksk5h5oqwtbkh1y1ogtz46o");
}

template <typename Lhs, typename Rhs> concept comparable = requires(const Lhs & l, const Rhs & r) {
	{ l == r } -> std::convertible_to<bool>;
};

TEST_CASE("in and out sha3") {
	// read from somewhere already calculated
	auto base64_parsed = cthash::sha3_256_value{cthash::base64, "A0idtwV8rNRViuLCPg6DIPPUIkd69a7lLB9SiE5u/Oc="sv};

	// calculating from
	auto calculated = cthash::sha3_256("aloha").final();
	REQUIRE(base64_parsed == calculated);

	// they can't even be compared! because they are different type
	REQUIRE_FALSE((comparable<decltype(calculated), cthash::sha256_value>));

	// literal
	auto hexdec_parsed = "03489db7057cacd4558ae2c23e0e8320f3d422477af5aee52c1f52884e6efce7"_sha3_256;
	REQUIRE(hexdec_parsed == calculated);
	REQUIRE(base64_parsed == calculated);

	// and encode into base32 (lazily, hence the helper)
	auto converted = calculated | cthash::encode(cthash::z_base32) | std::ranges::to<std::string>();
	REQUIRE(converted == "yprj5pafx1speickhmbdhdwdrd37ee18xm4473jcd7jeouuq9uuo");

	auto printed = std::format("{:z_base32}", calculated);
	REQUIRE(printed == converted);
}
