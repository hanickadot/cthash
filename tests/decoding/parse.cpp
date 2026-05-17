#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cthash/cthash.hpp>
#include <sstream>

using namespace std::string_view_literals;
using namespace cthash::literals;

template <typename> struct identify;

TEST_CASE("parse base64 sha256") {
	std::optional<cthash::sha256_value> hash = cthash::sha256::parse<cthash::base64>("AgapeEOxuk+7FH1HJVDsO17oqsrfNwdSIVckCUDRvr0="sv);
	REQUIRE(hash.has_value());
	REQUIRE(*hash == "0206a97843b1ba4fbb147d472550ec3b5ee8aacadf3707522157240940d1bebd"_sha256);
}
